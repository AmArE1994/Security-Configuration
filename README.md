# Detecting_a_malicious_http_request

#Analyzing_Malicious_pattern

SecurityRule REQUEST_BODY"+malicious+pattern"
"t:none,ctl:ResponseBodyAccess=On,Msg:'-IN-PTTRN path detected',
phase:2,pass,log,auditlog,id:10001',t:urlDecode,t:lowercase,serverity:1"


SecurityRule RESPONSE_BODY"root\:x\:0\:0"
"d:'20001',ctl:AuditLogParts=+E,msg:'-OUT- Content Detected!',
phase:4,allow,log,auditlog,t:lowercase,serverity:0"
