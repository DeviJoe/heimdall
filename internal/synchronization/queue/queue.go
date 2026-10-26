// Package queue transports durable synchronization wakeups. PostgreSQL remains
// authoritative; RabbitMQ delivery never counts as a Linux apply acknowledgement.
package queue

import (
	"context"
	"errors"
	amqp "github.com/rabbitmq/amqp091-go"
	"log/slog"
	"math/rand/v2"
	"sync/atomic"
	"time"
)

type Repository interface {
	PublishOutbox(context.Context, func(context.Context, string) error) error
}
type Queue struct {
	URL       string
	Store     Repository
	Wake      func(context.Context) error
	connected atomic.Bool
}

func (q *Queue) Connected() bool { return q.connected.Load() }
func (q *Queue) Run(ctx context.Context) {
	for ctx.Err() == nil {
		err := q.session(ctx)
		q.connected.Store(false)
		if ctx.Err() != nil {
			return
		}
		slog.Error("synchronization queue disconnected; reconciliation polling continues", "error", err)
		timer := time.NewTimer(time.Second + time.Duration(rand.IntN(4000))*time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func publish(ctx context.Context, ch *amqp.Channel, exchange, key, id string) error {
	confirm, err := ch.PublishWithDeferredConfirmWithContext(ctx, exchange, key, false, false, amqp.Publishing{DeliveryMode: amqp.Persistent, ContentType: "text/plain", MessageId: id, Body: []byte(id)})
	if err != nil {
		return err
	}
	if confirm == nil {
		return errors.New("publisher confirmations disabled")
	}
	ok, err := confirm.WaitContext(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("broker rejected synchronization wakeup")
	}
	return nil
}
func (q *Queue) session(ctx context.Context) error {
	conn, err := amqp.Dial(q.URL)
	if err != nil {
		return err
	}
	defer conn.Close()
	publisher, err := conn.Channel()
	if err != nil {
		return err
	}
	defer publisher.Close()
	if err = publisher.Confirm(false); err != nil {
		return err
	}
	if _, err = publisher.QueueDeclare("heimdall.sync.tasks", true, false, false, false, amqp.Table{"x-queue-type": "quorum"}); err != nil {
		return err
	}
	if err = publisher.ExchangeDeclare("heimdall.sync.wake", "fanout", false, true, false, false, nil); err != nil {
		return err
	}
	worker, err := conn.Channel()
	if err != nil {
		return err
	}
	defer worker.Close()
	if err = worker.Qos(32, 0, false); err != nil {
		return err
	}
	if err = worker.Confirm(false); err != nil {
		return err
	}
	jobs, err := worker.Consume("heimdall.sync.tasks", "", false, false, false, false, nil)
	if err != nil {
		return err
	}
	receiver, err := conn.Channel()
	if err != nil {
		return err
	}
	defer receiver.Close()
	eventsQueue, err := receiver.QueueDeclare("", false, true, true, false, nil)
	if err != nil {
		return err
	}
	if err = receiver.QueueBind(eventsQueue.Name, "", "heimdall.sync.wake", false, nil); err != nil {
		return err
	}
	if err = receiver.Qos(1, 0, false); err != nil {
		return err
	}
	events, err := receiver.Consume(eventsQueue.Name, "", false, true, false, false, nil)
	if err != nil {
		return err
	}
	failures := conn.NotifyClose(make(chan *amqp.Error, 1))
	q.connected.Store(true)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	wakePending := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failures:
			if err == nil {
				return errors.New("broker connection closed")
			}
			return err
		case <-ticker.C:
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = q.Store.PublishOutbox(bounded, func(ctx context.Context, id string) error {
				return publish(ctx, publisher, "", "heimdall.sync.tasks", id)
			})
			cancel()
			if err != nil {
				return err
			}
			if wakePending {
				bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
				err = q.Wake(bounded)
				cancel()
				if err != nil {
					return err
				}
				wakePending = false
			}
		case job, ok := <-jobs:
			if !ok {
				return errors.New("task consumer closed")
			}
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = publish(bounded, worker, "heimdall.sync.wake", "", job.MessageId)
			cancel()
			if err != nil {
				return err
			}
			if err = job.Ack(false); err != nil {
				return err
			}
		case event, ok := <-events:
			if !ok {
				return errors.New("wake consumer closed")
			}
			wakePending = true // Coalesce bursts; durable desired revisions also have a polling fallback.
			if err = event.Ack(false); err != nil {
				return err
			}
		}
	}
}
