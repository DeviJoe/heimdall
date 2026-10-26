#!/usr/bin/env python3
"""Generate the provisioned Grafana dashboard from maintained PromQL queries."""
import json, pathlib, re
ROOT = pathlib.Path(__file__).resolve().parent.parent
queries = [
 ('Ожидают перевыпуска сертификата', 'max(heimdall_certificates_pending)', 'stat', 'short', 'pending certificates'),
 ('Возраст перевыпуска сертификатов', 'max(heimdall_certificate_rollout_oldest_seconds)', 'timeseries', 's', 'certificate rollout'),
 ('Control plane', 'up{job="linpam"}', 'stat', 'short', '{{instance}}'),
 ('Подключения агентов', 'heimdall_agent_connections', 'timeseries', 'short', '{{instance}}'),
 ('Состояние синхронизации нод', 'max by(phase) (heimdall_nodes)', 'timeseries', 'short', '{{phase}}'),
 ('Ожидают применения', 'max(heimdall_sync_pending_nodes)', 'stat', 'short', 'pending'),
 ('Возраст неподтверждённых изменений', 'max(heimdall_sync_oldest_pending_seconds)', 'timeseries', 's', 'oldest'),
 ('Неподтверждённые блокировки', 'max(heimdall_revocation_pending_nodes)', 'timeseries', 'short', 'revocations'),
 ('RabbitMQ', 'heimdall_queue_connected', 'stat', 'short', '{{instance}}'),
 ('Возраст outbox', 'max(heimdall_outbox_oldest_pending_seconds)', 'timeseries', 's', 'outbox'),
 ('Задачи RabbitMQ', 'rabbitmq_queue_messages', 'timeseries', 'short', 'tasks'),
 ('Возраст доставки уведомлений', 'max(heimdall_notification_oldest_pending_seconds)', 'timeseries', 's', 'notifications'),
 ('Инциденты', 'max(heimdall_incidents_active)', 'stat', 'short', 'incidents'),
 ('Возраст проверки синхронизации', 'time() - heimdall_sync_detector_timestamp_seconds', 'timeseries', 's', '{{instance}}'),
 ('Память control plane', 'process_resident_memory_bytes{job="linpam"}', 'timeseries', 'bytes', '{{instance}}'),
 ('CPU control plane', 'rate(process_cpu_seconds_total{job="linpam"}[1m])', 'timeseries', 'short', '{{instance}}'),
 ('Goroutines', 'go_goroutines{job="linpam"}', 'timeseries', 'short', '{{instance}}'),
 ('Heartbeat нод', 'max by(state) (heimdall_nodes_connectivity)', 'timeseries', 'short', '{{state}}'),
 ('Ошибки каталогов', 'heimdall_directory_failed', 'timeseries', 'short', '{{provider}} / {{instance}}'),
 ('Возраст синхронизации каталога', 'time() - heimdall_directory_last_success_timestamp_seconds', 'timeseries', 's', '{{provider}} / {{instance}}'),
]
panels=[]
for i,(title,expr,kind,unit,legend) in enumerate(queries):
 panels.append({'id':i+1,'title':title,'type':kind,'datasource':{'type':'prometheus','uid':'heimdall-prometheus'},'gridPos':{'x':(i%2)*12,'y':(i//2)*8,'w':12,'h':8},'targets':[{'expr':expr,'legendFormat':legend,'refId':'A'}],'fieldConfig':{'defaults':{'unit':unit,'min':0,'color':{'mode':'palette-classic'}},'overrides':[]},'options':{'legend':{'displayMode':'list','placement':'bottom'},'tooltip':{'mode':'multi'}}})
for panel in panels:
 if panel['type']=='stat':
  good_one=panel['title'] in ['Control plane','RabbitMQ']
  panel['fieldConfig']['defaults'].update({'color':{'mode':'thresholds'},'thresholds':{'mode':'absolute','steps':[{'color':'red' if good_one else 'green','value':None},{'color':'green' if good_one else 'red','value':1}]}})
  panel['options'].update({'colorMode':'value','graphMode':'none','textMode':'auto','reduceOptions':{'calcs':['lastNotNull'],'fields':'','values':False}})
dashboard={'uid':'heimdall-operations','title':'Heimdall','schemaVersion':41,'version':1,'editable':True,'tags':['linpam'],'timezone':'browser','refresh':'5s','time':{'from':'now-30m','to':'now'},'panels':panels,'annotations':{'list':[{'name':'Alerts','type':'dashboard','builtIn':1,'enable':True,'hide':True}]}}
folder=ROOT/'deployments/grafana/dashboards';folder.mkdir(parents=True,exist_ok=True)
for job,queue_job,uid,title,filename in [
 ('heimdall','rabbitmq','heimdall-operations','Heimdall','heimdall.json'),
 ('heimdall-load','rabbitmq-load','heimdall-load','Heimdall · нагрузка','heimdall-load.json'),
]:
 copy=json.loads(json.dumps(dashboard))
 copy.update(uid=uid,title=title,tags=['heimdall'])
 for panel in copy['panels']:
  for target in panel['targets']:
   expr=target['expr'].replace('job="linpam"','job="'+job+'"')
   expr=re.sub(r'\b(heimdall_[a-z_]+)\b', lambda m:m[1]+'{job="'+job+'"}',expr)
   expr=expr.replace('rabbitmq_queue_messages','rabbitmq_queue_messages{job="'+queue_job+'"}')
   target['expr']=expr
 (folder/filename).write_text(json.dumps(copy,ensure_ascii=False,indent=2)+'\n')
legacy=folder/'linpam.json'
legacy.unlink(missing_ok=True)
print('Generated two Grafana dashboards:',len(panels),'panels each')
