package launcher

import (
	"Heimdall/internal/agent/client"
	"errors"
	"flag"
	"fmt"
	"go.yaml.in/yaml/v3"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	API            string        `yaml:"api"`
	GRPC           string        `yaml:"grpc"`
	ServerName     string        `yaml:"server_name"`
	Name           string        `yaml:"name"`
	StateDir       string        `yaml:"state_dir"`
	CAFile         string        `yaml:"ca_file"`
	Socket         string        `yaml:"socket"`
	Heartbeat      time.Duration `yaml:"heartbeat"`
	WorkerStateDir string        `yaml:"worker_state_dir"`
	StateKey       string        `yaml:"state_key"`
	AuthLog        string        `yaml:"auth_log"`
	RunAs          string        `yaml:"run_as"`
	JoinToken      string        `yaml:"join_token"`
	RecoveryToken  string        `yaml:"recovery_token"`
	Recover        bool          `yaml:"-"`
	InternalClient bool          `yaml:"-"`
}

func Parse(args []string) (Config, error) {
	hostname, _ := os.Hostname()
	c := Config{API: "https://controlplane:8443", GRPC: "controlplane:9443", ServerName: "controlplane", Name: hostname, StateDir: "/var/lib/heimdall-agent", CAFile: "/trust/ca.pem", Socket: "/run/linpam/helper.sock", Heartbeat: 15 * time.Second, WorkerStateDir: "/var/lib/heimdall-helper", StateKey: "/trust/state.pub", AuthLog: "/var/log/auth.log", RunAs: "heimdall-agent"}
	file := os.Getenv("HEIMDALL_AGENT_CONFIG")
	for i, arg := range args {
		if arg == "-config" || arg == "--config" {
			if i+1 >= len(args) {
				return c, errors.New("config path required")
			}
			file = args[i+1]
		}
		if strings.HasPrefix(arg, "-config=") || strings.HasPrefix(arg, "--config=") {
			_, file, _ = strings.Cut(arg, "=")
		}
	}
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return c, err
		}
		defer f.Close()
		decoder := yaml.NewDecoder(io.LimitReader(f, 1<<20))
		decoder.KnownFields(true)
		if err = decoder.Decode(&c); err != nil {
			return c, fmt.Errorf("agent YAML: %w", err)
		}
		var extra any
		if err = decoder.Decode(&extra); err != io.EOF {
			return c, errors.New("one YAML document required")
		}
		info, err := f.Stat()
		if err != nil {
			return c, err
		}
		if os.Geteuid() == 0 {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
				return c, errors.New("root agent YAML must be root-owned and non-writable by other users")
			}
		}
		if (c.JoinToken != "" || c.RecoveryToken != "") && info.Mode().Perm()&0077 != 0 {
			return c, errors.New("agent YAML containing tokens must have mode 0600")
		}
	}
	environment := map[string]*string{"HEIMDALL_AGENT_API": &c.API, "HEIMDALL_AGENT_GRPC": &c.GRPC, "HEIMDALL_AGENT_SERVER_NAME": &c.ServerName, "HEIMDALL_AGENT_NAME": &c.Name, "HEIMDALL_AGENT_STATE_DIR": &c.StateDir, "HEIMDALL_AGENT_CA": &c.CAFile, "HEIMDALL_AGENT_SOCKET": &c.Socket, "HEIMDALL_AGENT_WORKER_STATE_DIR": &c.WorkerStateDir, "HEIMDALL_AGENT_STATE_KEY": &c.StateKey, "HEIMDALL_AGENT_AUTH_LOG": &c.AuthLog, "HEIMDALL_AGENT_RUN_AS": &c.RunAs, "HEIMDALL_JOIN_TOKEN": &c.JoinToken, "HEIMDALL_RECOVERY_TOKEN": &c.RecoveryToken}
	if value := os.Getenv("HEIMDALL_NODE_NAME"); value != "" {
		c.Name = value
	}
	for key, target := range environment {
		if value, ok := os.LookupEnv(key); ok {
			*target = value
		}
	}
	if value := os.Getenv("HEIMDALL_AGENT_HEARTBEAT"); value != "" {
		var err error
		c.Heartbeat, err = time.ParseDuration(value)
		if err != nil {
			return c, errors.New("invalid agent heartbeat")
		}
	}
	flags := flag.NewFlagSet("heimdall-agent", flag.ContinueOnError)
	flags.StringVar(&file, "config", file, "YAML configuration; ENV and flags override it")
	flags.StringVar(&c.API, "api", c.API, "enrollment URL")
	flags.StringVar(&c.GRPC, "grpc", c.GRPC, "gRPC address")
	flags.StringVar(&c.ServerName, "server-name", c.ServerName, "TLS server name")
	flags.StringVar(&c.Name, "name", c.Name, "node name")
	flags.StringVar(&c.StateDir, "state-dir", c.StateDir, "network identity directory")
	flags.StringVar(&c.CAFile, "ca", c.CAFile, "TLS CA")
	flags.StringVar(&c.Socket, "helper", c.Socket, "local privileged worker socket")
	flags.StringVar(&c.WorkerStateDir, "worker-state-dir", c.WorkerStateDir, "root checkpoint directory")
	flags.StringVar(&c.StateKey, "state-key", c.StateKey, "state signature verification key")
	flags.StringVar(&c.AuthLog, "auth-log", c.AuthLog, "OpenSSH log")
	flags.StringVar(&c.RunAs, "run-as", c.RunAs, "unprivileged network service identity")
	flags.DurationVar(&c.Heartbeat, "heartbeat", c.Heartbeat, "heartbeat interval")
	flags.BoolVar(&c.Recover, "recover", false, "explicit certificate recovery and exit")
	flags.BoolVar(&c.InternalClient, "internal-client", false, "internal unprivileged subprocess")
	if err := flags.Parse(args); err != nil {
		return c, err
	}
	if c.InternalClient {
		return c, nil
	}
	if c.Heartbeat < time.Second || c.Heartbeat > 5*time.Minute || strings.TrimSpace(c.Name) == "" || len(c.Name) > 120 {
		return c, errors.New("invalid node name or heartbeat")
	}
	for _, path := range []string{c.StateDir, c.WorkerStateDir, c.Socket, c.CAFile, c.StateKey, c.AuthLog} {
		if !filepath.IsAbs(path) {
			return c, errors.New("agent paths must be absolute")
		}
	}
	if filepath.Clean(c.StateDir) == filepath.Clean(c.WorkerStateDir) {
		return c, errors.New("root and network state directories must differ")
	}
	runtimeDir := filepath.Dir(c.Socket)
	if runtimeDir == filepath.Clean(c.StateDir) || runtimeDir == filepath.Clean(c.WorkerStateDir) || runtimeDir == "/" || runtimeDir == "/run" || runtimeDir == "/var/run" || runtimeDir == "/tmp" || runtimeDir == "/etc" {
		return c, errors.New("agent socket requires its own root-owned runtime directory")
	}
	return c, nil
}
func (c Config) Client() client.Config {
	return client.Config{API: c.API, GRPC: c.GRPC, ServerName: c.ServerName, Name: c.Name, Directory: c.StateDir, CAFile: c.CAFile, Socket: c.Socket, Heartbeat: c.Heartbeat, JoinToken: c.JoinToken, RecoveryToken: c.RecoveryToken}
}
