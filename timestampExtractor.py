import datetime
import pytz
from dateutil import parser
import json
import re

def getAuditTimestamp(line):
    start = line.find('audit(')
    start += 6  # Move past 'audit('
    end = line.find(')', start)
    ts_part = line[start:end].split(':', 1)[0]
    timestamp = datetime.datetime.utcfromtimestamp(float(ts_part))
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeAuditTimestamp(line):
    return re.sub(r'audit\([^)]*\)', 'audit()', line) # Remove timestamp and ID
    #start = line.find('audit(')
    #start += 6  # Move past 'audit('
    #end = line.find(')', start)
    #return line[:start] + line[end:]

def getAuditId(line):
    start = line.find('audit(')
    start += 6  # Move past 'audit('
    end = line.find(')', start)
    id_part = line[start:end].split(':', 1)[1]
    return id_part

def getAuditProctitle(line):
    match = re.search(r"proctitle=([^\n]*)", line)
    if match is not None:
        return match.group(1)
    else:
        return None
def getEximTimestamp(line):
    parts = line.split(" ")
    timestamp = None
    timestamp = datetime.datetime.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeEximTimestamp(line):
    return line[20:]

def getSyslogTimestamp(line):
  timestamp = None
  try:
      timestamp = datetime.datetime.strptime("2025 " + line[:15], "%Y %b %d %H:%M:%S") # be aware: syslog has no year, thus %Y is hardcoded!
      timestamp = timestamp.replace(tzinfo=pytz.utc)
  except:
      timestamp = datetime.datetime.strptime(line.split(" ")[0], "%Y-%m-%dT%H:%M:%S.%f%z")
  return timestamp

def removeSyslogTimestamp(line):
  try:
      datetime.datetime.strptime("2025 " + line[:15], "%Y %b %d %H:%M:%S")
      line = line[16:]
  except:
      try:
          parts = line.split(" ")
          datetime.datetime.strptime(parts[0], "%Y-%m-%dT%H:%M:%S.%f%z")
          line = " ".join(parts[1:])
      except:
          return line

  parts = line.split(" ")
  if len(parts) < 2:
      # Some syslog events are empty
      return line
  parts[1] = ''.join(c for c in parts[1] if not c.isdigit()) # remove digits to get rid of process id
  line = " ".join(parts)
  line = re.sub(r'(?<=Startup time was )\d+', '', line) # Remove timestamp
  line = re.sub(r'(?<=now )\d+', '', line) # Remove timestamp
  line = re.sub(r'(?<=restart counter is at )\d+', '', line) # Remove counter
  line = re.sub(r'\[[^\]]*\d+\.\d+[^\]]*\]', '', line) # some lines have timestamps in square brackets in the beginning; remove digits
  line = re.sub(r'(?<=ID=)\d+', '', line) # Remove ID
  line = re.sub(r'(?<=SPT=)\d+', '', line) # Remove ID
  line = re.sub(r"(Consumed )\d+\.\d+(s)", r"\1\2", line) # Consumed 6.691s # Remove consumed time duration
  line = re.sub(r"/:.*?trimmed on", "/: trimmed on", line) # fstrim[2657]: /: 21.8 GiB (23417053184 bytes) trimmed on /dev/vda1
  line = re.sub(r"^Source\s+\d{1,3}(?:\.\d{1,3}){3}\s+replaced\s+with\s+\d{1,3}(?:\.\d{1,3}){3}\s+\(\d+\.([^)]+)\)$", r"Source replaced with (\1)",line) # Source 152.53.15.127 replaced with 162.159.200.123 (2.debian.pool.ntp.org)
  line = re.sub(r'(?<=NETDB state saved; )\d+', '', line) # remove number of entries of netdb
  line = re.sub(r'(?<=NETDB state saved;  entries, )\d+', '', line) # remove time taken by netdb
  return line

def getJsonTimestamp(line):
  try:
    j = json.loads(line)
  except json.JSONDecodeError as e:
    raise ValueError("Invalid JSON") from e
  timestamp = datetime.datetime.strptime(j["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
  return timestamp

def removeJsonTimestamp(line):
  try:
    j = json.loads(line)
  except json.JSONDecodeError as e:
    return line
  j["timestamp"] = ""
  return str(json.dumps(j))

def getFastTimestamp(line):
  timestamp = None
  timestamp = datetime.datetime.strptime(line[:26], "%m/%d/%Y-%H:%M:%S.%f")
  timestamp = timestamp.replace(tzinfo=pytz.utc)
  return timestamp

def removeFastTimestamp(line):
  return line[28:]

def getAccessTimestamp(line):
  parts = line.split(" ")
  timestamp = None
  try:
      timestamp = datetime.datetime.strptime(parts[3][1:] + " " + parts[4][:-1], "%d/%b/%Y:%H:%M:%S %z")
  except:
      try:
          timestamp = datetime.datetime.strptime(parts[4][1:] + " " + parts[5][:-1], "%d/%b/%Y:%H:%M:%S %z")
      except:
          timestamp = datetime.datetime.strptime(parts[0], "%Y-%m-%dT%H:%M:%S.%f")
          timestamp = timestamp.replace(tzinfo=pytz.utc)
  return timestamp

def removeAccessTimestamp(line):
    parts = line.split(" ")
    try:
        datetime.datetime.strptime(parts[3][1:] + " " + parts[4][:-1], "%d/%b/%Y:%H:%M:%S %z")
        return " ".join(parts[:3] + parts[5:])
    except:
        try:
            datetime.datetime.strptime(parts[4][1:] + " " + parts[5][:-1], "%d/%b/%Y:%H:%M:%S %z")
            return " ".join(parts[:4] + parts[6:])
        except:
            return " ".join(parts[1:])

def getErrorTimestamp(line):
  timestamp = None
  timestamp = datetime.datetime.strptime(line[5:32], "%b %d %H:%M:%S.%f %Y")
  timestamp = timestamp.replace(tzinfo=pytz.utc)
  return timestamp

def removeErrorTimestamp(line):
  return "[" + line[32:]

def getSuricataTimestamp(line):
    parts = line.split(" ")
    timestamp = datetime.datetime.strptime(parts[0] + " " + parts[2], "%d/%m/%Y %H:%M:%S")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeSuricataTimestamp(line):
    parts = line.split(" ")
    return " ".join([parts[1]] + parts[3:])

def getMonitoringTimestamp(line):
    j = json.loads(line)
    timestamp = datetime.datetime.strptime(j["@timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeMonitoringTimestamp(line):
    j = json.loads(line)
    j["@timestamp"] = ""
    return str(json.dumps(j))

def getStandardTimestamp(line):
    timestamp = datetime.datetime.strptime(line[0:19], "%Y-%m-%d %H:%M:%S")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeStandardTimestamp(line):
    return line[19:]

def getCollectdTimestamp(line):
    timestamp = datetime.datetime.strptime(line[1:21], "%Y-%m-%d %H:%M:%S")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeCollectdTimestamp(line):
    return line[21:]

def getIsoTimestamp(line):
    timestamp = datetime.datetime.strptime(line[0:24], "%Y-%m-%dT%H:%M:%S.%fZ")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeIsoTimestamp(line):
    return line[24:]

def getDayTimestamp(line):
    timestamp = datetime.datetime.strptime(line[0:24], "%a %b %d %H:%M:%S %Y")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeDayTimestamp(line):
    return line[24:]

def getCommaTimestamp(line):
    timestamp = datetime.datetime.strptime(line[0:23], "%Y-%m-%d %H:%M:%S,%f")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeCommaTimestamp(line):
    return line[23:]

def getAptTimestamp(line):
    parts = line.strip("\n\r").split("\n")[0].split(" ")
    timestamp = datetime.datetime.strptime(parts[2] + " " + parts[4], "%Y-%m-%d %H:%M:%S")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeAptTimestamp(line):
    parts = line.split("\n")
    parts[0] = "Log started:"
    parts[-1] = "Log ended:"
    return "\n".join(parts)

def getHistoryTimestamp(line):
    parts = line.strip("\n\r").split("\n")[0].split(" ")
    timestamp = datetime.datetime.strptime(parts[1] + " " + parts[3], "%Y-%m-%d %H:%M:%S")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeHistoryTimestamp(line):
    parts = line.split("\n")
    parts[0] = "Start-Date:"
    parts[-1] = "End-Date:"
    return "\n".join(parts)

def getAlternativesTimestamp(line):
    parts = line.split(" ")
    timestamp = datetime.datetime.strptime(parts[1] + " " + parts[2], "%Y-%m-%d %H:%M:%S:")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeAlternativesTimestamp(line):
    parts = line.split(" ")
    return " ".join([parts[0]] + parts[3:])

def getZmXTimestamp(line):
    parts = line.split(" ")
    timestamp = datetime.datetime.strptime(parts[0] + " " + parts[1] + " " + parts[2] + " " + parts[3], "%m/%d/%y, %I:%M:%S %p UTC.%f")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeZmXTimestamp(line):
    parts = line.split(" ")
    return " ".join(parts[4:])

def getZmTimestamp(line):
    if line.startswith("Update agent starting at"):
        timestamp = datetime.datetime.strptime(line[25:42], "%y/%m/%d %H:%M:%S")
    else:
        timestamp = datetime.datetime.strptime(line[0:24], "%m/%d/%y %H:%M:%S.%f")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeZmTimestamp(line):
    if line.startswith("Update agent starting at"):
        return "Update agent starting at\n"
    else:
        parts = line.split(" ")
        parts[2] = ''.join(c for c in parts[2] if not c.isdigit()) # remove digits to get rid of process id
        line = " ".join(parts)
        line = line[24:]
        line = re.sub(r'(?<=\[ZMServer:)\d+(?=\])', '', line) # Remove ID
        line = re.sub(r'(?<=to pid )\d+', '', line) # Remove ID
        line = re.sub(r'(?<=at )\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}', '', line) # Remove timestamp
        line = re.sub(r'(?<=pid = )\d+', '', line) # Remove ID
        line = re.sub(r'(?<=Startup time was )\d+', '', line) # Remove timestamp
        line = re.sub(r'(?<=now )\d+', '', line) # Remove timestamp
        return line

def getCacheTimestamp(line):
    timestamp = datetime.datetime.strptime(line[0:19], "%Y/%m/%d %H:%M:%S")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeCacheTimestamp(line):
    line = line[19:]
    line = re.sub(r'(?<=NETDB state saved; )\d+', '', line) # remove number of entries of netdb
    line = re.sub(r'(?<=NETDB state saved;  entries, )\d+', '', line) # remove time taken by netdb
    return line

def getCollectdTimestamp(line):
    timestamp = datetime.datetime.strptime(line[1:20], "%Y-%m-%d %H:%M:%S")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeCollectdTimestamp(line):
    return line[20:]

def getAttackMateOutputTimestamp(line):
    timestamp = datetime.datetime.strptime(line[4:23], "%Y-%m-%d %H:%M:%S")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeAttackMateOutputTimestamp(line):
    return line[23:]

def getAttackMateOutputCommand(line):
    match = re.search(r"---\n\nCommand: ([^\n]*)", line)
    return match.group(1).strip("\n")

def getAttackMateTimestamp(line):
    j = json.loads(line)
    timestamp = datetime.datetime.strptime(j["start-datetime"], "%Y-%m-%dT%H:%M:%S.%f")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeAttackMateTimestamp(line):
    j = json.loads(line)
    j["start-datetime"] = ""
    return str(json.dumps(j))

def getWazuhJsonTimestamp(line):
    j = json.loads(line)
    location = j["location"]
    # Try to extract timestamp of original log that triggered the alert
    for keyword in timestampExtractor:
        if keyword in location and "full_log" in j:
            return timestampExtractor[keyword](j["full_log"])
    # Could not find match in full_log, resort to Wazuh timestamp instead
    timestamp = datetime.datetime.strptime(j["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
    return timestamp

def removeWazuhJsonTimestamp(line):
    j = json.loads(line)
    j["timestamp"] = ""
    j["firedtimes"] = 0 # Remove counter
    location = j["location"]
    # Also try to remove timestamp of original log that triggered the alert
    for keyword in timestampRemove:
        if keyword in location and "full_log" in j:
            j["full_log"] = timestampRemove[keyword](j["full_log"])
            break
    return str(json.dumps(j))

def getWazuhJsonHostname(line):
    j = json.loads(line)
    if "agent" in j and "name" in j["agent"]:
        return j["agent"]["name"]
    return None

def getWazuhLogTimestamp(line):
    parts = line.split(" ")
    timestamp = datetime.datetime.utcfromtimestamp(float(parts[2].replace(":", "")))
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeWazuhLogTimestamp(line):
    parts = line.split(" ")
    return " ".join(parts[:2] + parts[3:])

def getWazuhLogHostname(line):
    return line.split("\n")[1].split(" ")[4].split("-")[0].strip("()")

def getWazuhSeverity(line):
    j = json.loads(line)
    if "rule" in j and "level" in j["rule"]:
        return str(j["rule"]["level"])
    else:
        return None

def getFastSeverity(line):
    match = re.search(r"\[Priority:\s*(\d+)\]", line)
    if match:
        return match.group(1)
    else:
        return None

def getDockerContainerTimestamp(line):
    j = json.loads(line)
    ts_without_nanosec = j["time"][:26]
    timestamp = datetime.datetime.strptime(ts_without_nanosec, "%Y-%m-%dT%H:%M:%S.%f")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeDockerContainerTimestamp(line):
    j = json.loads(line)
    j["time"] = ""
    return str(json.dumps(j))

def getNcLogTimestamp(line):
    j = json.loads(line)
    timestamp = datetime.datetime.strptime(j["time"], "%Y-%m-%dT%H:%M:%S%z")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeNcLogTimestamp(line):
    j = json.loads(line)
    j["time"] = ""
    j["reqId"] = ""
    j["message"] = re.sub(r'(?<=with ID )\d+', '', j["message"])
    return str(json.dumps(j))

def getApportTimestamp(line):
    parts = line.split(" ")
    timestamp = datetime.datetime.strptime(parts[5] + " " + parts[6], "%Y-%m-%d %H:%M:%S,%f")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeApportTimestamp(line):
    parts = line.split(" ")
    return " ".join(parts[:5] + parts[7:])

def getHealthcheckdTimestamp(line):
    parts = line.split(" ")
    timestamp = datetime.datetime.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S")
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

def removeHealthcheckdTimestamp(line):
    parts = line.split(" ")
    return " ".join(parts[2:])

timestampExtractor = {
"/audit/audit.log": getAuditTimestamp,
"/auth.log": getSyslogTimestamp,
"/mail.log": getSyslogTimestamp,
"/mail.info": getSyslogTimestamp,
"/mail.warn": getSyslogTimestamp,
"/mainlog": getEximTimestamp,
"/messages": getSyslogTimestamp,
"/eve.json": getJsonTimestamp,
"/fast.log": getFastTimestamp,
"/daemon.log": getSyslogTimestamp,
"/syslog": getSyslogTimestamp,
"/user.log": getSyslogTimestamp,
"-access.log": getAccessTimestamp,
"/access.log": getAccessTimestamp,
"-error.log": getErrorTimestamp,
"/error.log": getErrorTimestamp,
"/suricata.log": getSuricataTimestamp,
"/kern.log": getSyslogTimestamp,
"/dnsmasq.log": getSyslogTimestamp,
"/other_vhosts_access.log": getAccessTimestamp,
"/logstash/internal-share/": getMonitoringTimestamp,
"/logstash/intranet-server/": getMonitoringTimestamp,
"/collectd.log": getCollectdTimestamp,
"/puppetserver-access-": getAccessTimestamp,
"/puppetserver.log": getIsoTimestamp,
"/puppetserver-20": getIsoTimestamp,
"/vsftpd.log": getDayTimestamp,
"/cloud-init.log": getCommaTimestamp,
"/unattended-upgrades.log": getCommaTimestamp,
"/shorewall-init.log": getSyslogTimestamp,
"/term.log": getAptTimestamp,
"/history.log": getHistoryTimestamp,
"/dpkg.log": getStandardTimestamp,
"/unattended-upgrades-dpkg.log": getAptTimestamp,
"/unattended-upgrades-shutdown.log": getCommaTimestamp,
"/alternatives.log": getAlternativesTimestamp,
"/zm/web_php.log": getZmXTimestamp,
"/zm/z": getZmTimestamp,
"/debug": getSyslogTimestamp,
"/cache.log": getCacheTimestamp,
"/attacker/logs/output.log": getAttackMateOutputTimestamp,
"/adminpc/logs/output.log": getAttackMateOutputTimestamp,
"/attackmate.log": getStandardTimestamp,
"/attackmate.json": getAttackMateTimestamp,
"/alerts.json": getWazuhJsonTimestamp,
"/alerts.log": getWazuhLogTimestamp,
"-json.log": getDockerContainerTimestamp,
"/nclog/audit.log": getNcLogTimestamp,
"/nclog/nextcloud.log": getNcLogTimestamp,
"/apport.log": getApportTimestamp,
"/cron.log": getSyslogTimestamp,
"/healthcheckd.log": getHealthcheckdTimestamp,
}

timestampRemove = {
"/audit/audit.log": removeAuditTimestamp,
"/auth.log": removeSyslogTimestamp,
"/mail.log": removeSyslogTimestamp,
"/mail.info": removeSyslogTimestamp,
"/mail.warn": removeSyslogTimestamp,
"/mainlog": removeEximTimestamp,
"/messages": removeSyslogTimestamp,
"/eve.json": removeJsonTimestamp,
"/fast.log": removeFastTimestamp,
"/daemon.log": removeSyslogTimestamp,
"/syslog": removeSyslogTimestamp,
"/user.log": removeSyslogTimestamp,
"-access.log": removeAccessTimestamp,
"/access.log": removeAccessTimestamp,
"-error.log": removeErrorTimestamp,
"/error.log": removeErrorTimestamp,
"/suricata.log": removeSuricataTimestamp,
"/kern.log": removeSyslogTimestamp,
"/dnsmasq.log": removeSyslogTimestamp,
"/other_vhosts_access.log": removeAccessTimestamp,
"/logstash/internal-share/": removeMonitoringTimestamp,
"/logstash/intranet-server/": removeMonitoringTimestamp,
"/collectd.log": removeCollectdTimestamp,
"/puppetserver-access-": removeAccessTimestamp,
"/puppetserver.log": removeIsoTimestamp,
"/puppetserver-20": removeIsoTimestamp,
"/vsftpd.log": removeDayTimestamp,
"/cloud-init.log": removeCommaTimestamp,
"/unattended-upgrades.log": removeCommaTimestamp,
"/shorewall-init.log": removeSyslogTimestamp,
"/term.log": removeAptTimestamp,
"/history.log": removeHistoryTimestamp,
"/dpkg.log": removeStandardTimestamp,
"/unattended-upgrades-dpkg.log": removeAptTimestamp,
"/unattended-upgrades-shutdown.log": removeCommaTimestamp,
"/alternatives.log": removeAlternativesTimestamp,
"/zm/web_php.log": removeZmXTimestamp,
"/zm/z": removeZmTimestamp,
"/debug": removeSyslogTimestamp,
"/cache.log": removeCacheTimestamp,
"/attacker/logs/output.log": removeAttackMateOutputTimestamp,
"/adminpc/logs/output.log": removeAttackMateOutputTimestamp,
"/attackmate.log": removeStandardTimestamp,
"/attackmate.json": removeAttackMateTimestamp,
"/alerts.json": removeWazuhJsonTimestamp,
"/alerts.log": removeWazuhLogTimestamp,
"-json.log": removeDockerContainerTimestamp,
"/nclog/audit.log": removeNcLogTimestamp,
"/nclog/nextcloud.log": removeNcLogTimestamp,
"/apport.log": removeApportTimestamp,
"/cron.log": removeSyslogTimestamp,
"/healthcheckd.log": removeHealthcheckdTimestamp,
}

idExtractor = {
"/audit/audit.log": getAuditId,
}

hostnameExtractor = {
"/alerts.json": getWazuhJsonHostname,
"/alerts.log": getWazuhLogHostname,
}

severityExtractor = {
"/alerts.json": getWazuhSeverity,
"/fast.log": getFastSeverity,
}
