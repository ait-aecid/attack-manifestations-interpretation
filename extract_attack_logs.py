import os
import timestampExtractor
import chardet
import lzma
import gzip
import re
import json
import shutil
from datetime import datetime, timedelta
from tqdm import tqdm

data_dir = "data/"
manifestations_dir = "manifestations_filtered/techniques/"
seq_dir = "manifestations_filtered/sequences/"
event_dir = "manifestations_filtered/steps/"
manifestations_raw_dir = "manifestations_raw/techniques/"
seq_raw_dir = "manifestations_raw/sequences/"
event_raw_dir = "manifestations_raw/steps/"

id_filepaths = {}
max_filename_length = 250
factor_reduce = 10
get_audit_proctitles = False
audit_proctitles = {}
filter_logs_all_scenarios = True
print_event_id_info = False
print_state_charts = True
output_na_techniques = False
detailed_output = False

if print_state_charts:
    from graphviz import Digraph

fix_time_start = {"1_autostart_sshkey": {15: -82}, # include curl and start of vim to command injection
                  "1_autostart_localaccount": {15: -82}, # include curl and start of vim to command injection
                  "1_autostart_pam": {15: -82}, # include curl and start of vim to command injection
                  "3_ssh_healthcheck": {9: -71}, # include vim open
                  "6_macro_binary": {22: 40}, # enlarge to capture cron-triggered exfiltration
                  "6_macro_cron": {22: 40}, # enlarge to capture cron-triggered exfiltration
                  "6_screensharing_binary": {22: 40, # enlarge to capture cron-triggered exfiltration
                                             45: -150, # enlarge to capture connection establishment
                                             47: -60}, # enlarge to capture connection establishment
                  "6_screensharing_cron": {22: 40, # enlarge to capture cron-triggered exfiltration
                                           45: -150, # enlarge to capture connection establishment
                                           47: -60}, # enlarge to capture connection establishment
                  }
fix_time_end = {"1_autostart_sshkey": {16: 93}, # restart and login takes longer than expected
                "1_autostart_localaccount": {16: 93}, # restart and login takes longer than expected
                "1_autostart_pam": {16: 93}, # restart and login takes longer than expected
                "1_racecondition_sshkey": {52: 671}, # delayed manifestation of racecondition
                "1_racecondition_localaccount": {52: 660, # delayed manifestation of racecondition
                                                 22: 2}, # wazuh lags behind
                "1_racecondition_pam": {52: 700}, # delayed manifestation of racecondition
                "1_cron_sshkey": {32: 504}, # delayed manifestation of cron
                "1_cron_localaccount": {32: 548}, # delayed manifestation of cron
                "1_cron_pam": {32: 695}, # delayed manifestation of cron
                "3_ssh_healthcheck": {1: 4, # brute-force takes longer than expected
                                    2: 3, # login takes longer than expected
                                    26: 3}, # ransomware takes longer than expected
                "3_ssh_apt": {1: 4, # brute-force takes longer than expected
                                    2: 3, # login takes longer than expected
                                    26: 3}, # ransomware takes longer than expected
                "3_ssh_puppet": {1: 4, # brute-force takes longer than expected
                                    2: 3, # login takes longer than expected
                                    26: 3, # ransomware takes longer than expected
                                    40: 180}, # waiting for puppet to execute code
                "3_vnc_healthcheck": {26: 3}, # ransomware takes longer than expected
                "3_vnc_apt": {26: 3}, # ransomware takes longer than expected
                "3_vnc_puppet": {26: 3, # ransomware takes longer than expected
                                 60: 75}, # waiting for puppet to execute code
                "6_macro_binary": {2: 10, # soffice command takes longer than expected
                                   21: 40, # merge vim edit and save commands
                                   22: 90, # move to capture cron-triggered exfiltration
                                   23: -885}, # undo time window enlargement due to sleep
                "6_macro_cron": {2: 10, # soffice command takes longer than expected
                                   21: 40, # merge vim edit and save commands
                                   22: 630, # move to capture cron-triggered exfiltration
                                   23: -885, # undo time window enlargement due to sleep
                                   24: 35}, # include crontab edit
                "6_screensharing_binary": {2: 10, # soffice command takes longer than expected
                                   21: 40, # merge vim edit and save commands
                                   22: 630, # move to capture cron-triggered exfiltration
                                   23: -885}, # undo time window enlargement due to sleep
                "6_screensharing_cron": {2: 10, # soffice command takes longer than expected
                                   21: 40, # merge vim edit and save commands
                                   22: 630, # move to capture cron-triggered exfiltration
                                   23: -885, # undo time window enlargement due to sleep
                                   24: 35}, # include crontab edit
                "6_plugin": {26: 9, # extend to include installation procedure
                             28: 5, # extend to include installation procedure
                             30: 8, # extend to include installation procedure
                             31: 5, # extend to include login
                             32: 24, # extend to include login
                             33: 20, # extend to include keylogger
                             34: 20, # extend to include keylogger
                             35: 35, # extend to include keylogger
                             36: 2}, # extend to include input capture
                }

whitelist = ["/logs/"]
blacklist = ["/wtmp", # binary file
             "/pacct", # binary file
             "/cloud-init-output.log", # no timestamps
             "/journal/", # binary file
             "/dmesg", # only relative timestamps
             "/log.pcap", # not relevant
             "/suricata/stats.log", # not relevant
             "/lastlog", # binary file
             "/faillog", # binary file
             "/lightdm/", # only relative timestamps
             "/gpu-manager.log", # no timestamps
             "/Xorg.0.log", # only relative timestamps
             "/btmp", # binary file
             "/.bash_history", # no timestamps
             "/eipp.log", # no timestamps
             "/sysstat/", # binary files
             "/.msf4/", # metasploit data only relevant for attacker
             "/fontconfig.log", # no timestamps
             "/README", # no timestamps
             "/apport.log", # only relevant for attacker
             "/rustdesk/", # only relevant for attacker
             "/x11vnc.log", # only relevant for attacker
             "/ossec-", # duplicated logs from wazuh
             ".swp", # swap files generated when opening files
             "/alerts.log", # duplicated information from /alerts.json
             "/hostconfig.json", # in docker logs
             "/hostname", # in docker logs
             "/hosts", # in docker logs
             "/resolv.conf", # in docker logs
             "/config.v2.json", # in docker logs
             "/README", # in docker logs
             "/accesss.log", # only added as part of attack, does not contain actual log data
             ]
multiline_end = {"/collectd.log": r"\n\n$",
                 "/term.log": r"Log ended:.*\n\n$",
                 "/unattended-upgrades-dpkg.log": r"Log ended:.*\n\n$",
                 "/history.log": r"End-Date:.*\n\n$",
                 "/alerts.log": r"\n\n$",}
multiline_start = {"/attacker/logs/output.log": r"^--- "}

log_filter_keywords = {
        "/audit/audit.log": ["proctitle=2F7573722F62696E2F7065726C002D7754002F7573722F62696E2F7A6D64632E706C0073746172747570", # zm process
                       "proctitle=2F7573722F62696E2F7065726C002D7754002F7573722F62696E2F7A6D64632E706C0072657374617274007A6D63002D6D0031", # zm process
                       "proctitle=6466002F7661722F63616368652F7A6F6E656D696E6465722F6576656E7473", # zm process
                       "proctitle=756E616D65002D6D", # uname
                       "GID=\"wazuh\"", # wazuh activity
                       "proctitle=\"/usr/lib/snapd/snapd\"", # periodically
                       "proctitle=\"/lib/systemd/systemd-timesyncd\"", # periodically
                       "proctitle=\"(imedated)\"", # system time checks
                       "proctitle=2F7573722F7362696E2F6368726F6E7964002D460031", # chronyd time-sync
                       "proctitle=\"(install)\"", # part of mandb housekeeping
                       "proctitle=\"(find)\"", # part of mandb housekeeping
                       "proctitle=\"(mandb)\"", # part of mandb housekeeping
                       "proctitle=\"(tmpfiles)\"", # normal systemd activity
                       "proctitle=\"(fstrim)\"", # normal systemd activity
                       "proctitle=2F7573722F62696E2F727573746465736B002D2D73657276696365", # rustdesk
                       "proctitle=2F7573722F73686172652F727573746465736B2F727573746465736B002D2D736572766572", # rustdesk
                       "proctitle=\"rustdesk\"", # rustdesk
                       "proctitle=7067726570002D6100587761796C616E64", # rustdesk
                       "proctitle=2873717569642D3129002D2D6B69640073717569642D31002D2D666F726567726F756E64002D735943", # rustdesk
                       "proctitle=2F7573722F7362696E2F43524F4E002D66002D50", # cron, periodically
                       "proctitle=2F7573722F62696E2F646F636B65720065786563002D75007777772D64617461002D77002F7661722F7777772F6E657874636C6F7564006E657874636C6F75642D6170702D310062617368002D6300706870202F7661722F7777772F6E657874636C6F75642F63726F6E2E706870203E202F6465762F6E756C6C", # docker, periodically
                       "proctitle=72756E63002D2D726F6F74002F7661722F72756E2F646F636B65722F72756E74696D652D72756E632F6D6F6279002D2D6C6F67002F72756E2F636F6E7461696E6572642F696F2E636F6E7461696E6572642E72756E74696D652E76322E7461736B2F6D6F62792F39643065663831346236346265653031386636346336646331", # docker, periodically
                       "proctitle=72756E6300696E6974", # docker, periodically
                       "proctitle=706870002F7661722F7777772F6E657874636C6F75642F63726F6E2E706870", # cron, periodically
                       "proctitle=\"/var/ossec/bin/wazuh-logcollector\"", # wazuh
                                      ],
                       "/error.log": [#"Graceful restart requested, doing restart" # do not filter, occurs during linpeas
                           ],
                       "/alerts.json": [#"\"description\":\"Log file rotated.\"", # occurs randomly as wazuh alert # also triggers other logs # may be caused in logrotten attack
                                        "SURICATA STREAM excessive retransmissions", # occurs randomly
                                        "SURICATA STREAM Packet with invalid timestamp", # occurs randomly
                                        "SURICATA STREAM pkt seen on wrong thread", # occurs periodically
                                        "ET INFO RustDesk Domain in DNS Lookup", # occurs periodically
                                        "First time this IDS alert is generated.", # duplicate of another alert
                                        "IDS event.", # duplicate of another alert
                           ],
                       "/fast.log": ["SURICATA STREAM excessive retransmissions", # occurs as part of attack
                                     "SURICATA STREAM Packet with invalid timestamp", # occurs randomly
                                     "SURICATA STREAM pkt seen on wrong thread", # occurs periodically
                                     "ET INFO RustDesk Domain in DNS Lookup", # occurs periodically
                                     ],
                       "/syslog": [
                           "Reloaded The Apache HTTP Server.", # occurs randomly
                           "Reloading The Apache HTTP Server.", # occurs randomly
                           ".debian.pool.ntp.org", # time-sync
                           "Starting motd-news.service - Message of the Day...", # motd-news
                           "* Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s",  # motd-news
                           "just raised the bar for easy, resilient and secure K8s cluster deployment.",  # motd-news
                           "https://ubuntu.com/engage/secure-kubernetes-at-the-edge",  # motd-news
                           "motd-news.service: Deactivated successfully.",  # motd-news
                           "Finished motd-news.service - Message of the Day.", # motd-news
                                   ],
                       "/daemon.log": [
                           "Reloaded The Apache HTTP Server.", # occurs randomly
                           "Reloading The Apache HTTP Server.", # occurs randomly
                           ".debian.pool.ntp.org", # time-sync
                                       ],
                       "/access.log": [
                               "192.168.50.100 TCP_MISS/503 4024 POST http://192.42.1.174:21114/api/heartbeat - HIER_DIRECT/192.42.1.174 text/html", # rustdesk periodic
                               "192.168.50.100 TCP_MISS/503 4018 POST http://192.42.1.174:21114/api/sysinfo - HIER_DIRECT/192.42.1.174 text/html", # rustdesk periodic
                               ],
                       "/nclog/nextcloud.log": [
                               "ExpireVersions", # occurs periodically but only rarely, not in training
                               "ExpireTrash", # occurs periodically but only rarely, not in training
                               ],
        }

log_filter_options = {} 

with open("mitre_matrix.json") as mitre_fh:
    mitre_mapping = json.load(mitre_fh)

def shorten_tactic(tactic):
    tactic = tactic.replace("Reconnaissance", "RCN")
    tactic = tactic.replace("Resource Development", "RSD")
    tactic = tactic.replace("Initial Access", "IA")
    tactic = tactic.replace("Execution", "EXE")
    tactic = tactic.replace("Persistence", "PST")
    tactic = tactic.replace("Privilege Escalation", "PVE")
    tactic = tactic.replace("Defense Evasion", "DEF")
    tactic = tactic.replace("Credential Access", "CRD")
    tactic = tactic.replace("Discovery", "DSC")
    tactic = tactic.replace("Lateral Movement", "LAT")
    tactic = tactic.replace("Collection", "COL")
    tactic = tactic.replace("Command and Control", "CNC")
    tactic = tactic.replace("Exfiltration", "EXF")
    tactic = tactic.replace("Impact", "IMP")
    return tactic

def open_log_file(filename):
    if filename.endswith(".xz"):
        return lzma.open(filename, 'rt')
    elif filename.endswith(".gz"):
        return gzip.open(filename, 'rt')
    else:
        return open(filename, 'r')

def reduce_ts(dt, factor_seconds) -> datetime:
    epoch = datetime(1970, 1, 1, tzinfo=dt.tzinfo)
    total = int((dt - epoch).total_seconds())
    reduced = (total // factor_seconds) * factor_seconds
    return epoch + timedelta(seconds=reduced)

def write_to_file(line, timestamp, full_path, attack_times_list, scenario_variant_file, keyword, new_line, seq_id_dict):
    if timestamp is None:
        print("WARNING: Omitting line \"" + line + "\" due to lack of timestamp in this and previous lines")
        return
    attack_time_dict_found = False
    log_path = full_path.replace(scenario_variant_file, "")
    if log_path.endswith(".gz"):
        # Remove .gz, file will be stored as unzipped file
        log_path = log_path[:-3]
    if keyword in ["/alerts.json", "/alerts.log"]:
        # In case of wazuh, use the host name of the agent to see where the alert occurred (only for timeline output)
        extracted_wazuh_hostname = timestampExtractor.hostnameExtractor[keyword](line)
        if extracted_wazuh_hostname is not None:
            log_path_out = extracted_wazuh_hostname
        else:
            log_path_out = log_path
    else:
        log_path_out = log_path
    scenario_variant_short = re.search(r".*/scenario_(.+)$", scenario_variant_file).group(1).strip("_") # r"_scenario(.*?)_(2025|2026)"
    for attack_time_dict in attack_times_list[scenario_variant_file]:
        attack_time_dict_start = attack_time_dict["start"]
        attack_time_dict_end = attack_time_dict["end"]
        if keyword == "/collectd.log":
            attack_time_dict_end += timedelta(seconds=10)
        if timestamp >= attack_time_dict_start and timestamp < attack_time_dict_end:
            if attack_time_dict_found is True and keyword != "/collectd.log": # collectd occurs periodically and can thus contain traces of multiple attack steps
                print("WARNING: Line fits in multiple attack time windows ")
                print(attack_time_dict)
                print(line)
                exit()
            attack_time_dict_found = True
            cmd_short = re.sub(r'[^a-zA-Z0-9 ]', '', attack_time_dict["cmd"]).split(" ")[0][:30]
            if cmd_short == "":
                cmd_short = "NA"
            for technique_full in attack_time_dict["metadata"]:
                tactics = attack_time_dict["metadata"][technique_full]["tactics"]
                if "." in technique_full:
                    technique, subtechnique = technique_full.split(".")
                else:
                    technique = technique_full
                    subtechnique = "000"
                full_path = manifestations_dir + technique + "-" + subtechnique + "/" + re.sub(r'[^a-zA-Z0-9]', '_', scenario_variant_short) + "-" + attack_time_dict["event_id"] + log_path # "-" + cmd_short + log_path
                if new_line == 1 and keyword != "/collectd.log" and keyword != "/eve.json":
                    # Write technique manifestations
                    os.makedirs(os.path.dirname(full_path), exist_ok = True)
                    with open(full_path, "a") as filehandle:
                        filehandle.write(line)
                # Write raw, unfiltered technique manifestations
                full_path = manifestations_raw_dir + technique + "-" + subtechnique + "/" + re.sub(r'[^a-zA-Z0-9]', '_', scenario_variant_short) + "-" + attack_time_dict["event_id"] + log_path # "-" + cmd_short + log_path
                os.makedirs(os.path.dirname(full_path), exist_ok = True)
                with open(full_path, "a") as filehandle:
                    filehandle.write(line)
                with open("logs.csv", "a") as logs_csv:
                    logs_csv.write(scenario_variant_short + "," + log_path_out + "," + re.sub(r'[^a-zA-Z0-9]', '_', "_".join(tactics)) + "," + technique + "," + subtechnique + "," + keyword + "," + attack_time_dict["event_id"] + "," + str(new_line) + "," + cmd_short + "," + str(timestamp.timestamp()) + "\n")
            full_path_step = event_dir + re.sub(r'[^a-zA-Z0-9]', '_', scenario_variant_short) + "-" + attack_time_dict["event_id"] + log_path
            if new_line == 1 and keyword != "/collectd.log" and keyword != "/eve.json":
                # Write step manifestation
                os.makedirs(os.path.dirname(full_path_step), exist_ok = True)
                with open(full_path_step, "a") as filehandle:
                    filehandle.write(line)
                # Write sequence manifestations
                for seq_id_list in seq_id_dict[scenario_variant_short][technique_full]:
                    if attack_time_dict["event_id"] in seq_id_list:
                        full_path_seq = seq_dir + re.sub(r'[^a-zA-Z0-9]', '_', scenario_variant_short) + "-" + '_'.join(seq_id_list) + log_path
                        os.makedirs(os.path.dirname(full_path_seq), exist_ok = True)
                        with open(full_path_seq, "a") as filehandle:
                            filehandle.write(line)
            full_path_step = event_raw_dir + re.sub(r'[^a-zA-Z0-9]', '_', scenario_variant_short) + "-" + attack_time_dict["event_id"] + log_path
            # Write raw, unfiltered step manifestations
            os.makedirs(os.path.dirname(full_path_step), exist_ok = True)
            with open(full_path_step, "a") as filehandle:
                filehandle.write(line)
            # Write raw, unfiltered sequence manifestations
            for seq_id_list in seq_id_dict[scenario_variant_short][technique_full]:
                if attack_time_dict["event_id"] in seq_id_list:
                    full_path_seq = seq_raw_dir + re.sub(r'[^a-zA-Z0-9]', '_', scenario_variant_short) + "-" + '_'.join(seq_id_list) + log_path
                    os.makedirs(os.path.dirname(full_path_seq), exist_ok = True)
                    with open(full_path_seq, "a") as filehandle:
                        filehandle.write(line)
            if get_audit_proctitles is True and keyword == "/audit/audit.log":
                if scenario_variant not in audit_proctitles:
                    audit_proctitles[scenario_variant] = {}
                audit_proctitle = timestampExtractor.getAuditProctitle(line)
                if audit_proctitle is not None:
                    if audit_proctitle not in audit_proctitles[scenario_variant]:
                        try:
                            audit_proctitle_decoded = bytes.fromhex(audit_proctitle).decode('utf-8')
                        except:
                            # proctitle is not encoded
                            audit_proctitle_decoded = ""
                        audit_proctitles[scenario_variant][audit_proctitle] = [audit_proctitle_decoded, timestamp, timestamp, 1, 1, 0] # proctitle decoded, first seen timestamp, last seen timestamp, first seen during attack, attack count, normal count
                    else:
                        audit_proctitles[scenario_variant][audit_proctitle][2] = timestamp # update last seen timestamp
                        audit_proctitles[scenario_variant][audit_proctitle][4] += 1
    if attack_time_dict_found is False:
        # Log is not within any attack interval; output for debugging!
        min_time = None
        for attack_time_dict in attack_times_list[scenario_variant_file]:
            if min_time is None or attack_time_dict["start"] < min_time:
                min_time = attack_time_dict["start"]
        if timestamp >= min_time - timedelta(minutes=5):
            if new_line == 1:
                if output_na_techniques:
                    new_path = manifestations_dir + "NA/" + scenario_variant_short + log_path
                    os.makedirs(os.path.dirname(new_path), exist_ok = True)
                    with open(new_path, "a") as new_fh:
                        new_fh.write(line)
                if get_audit_proctitles is True and keyword == "/audit/audit.log":
                    if scenario_variant not in audit_proctitles:
                        audit_proctitles[scenario_variant] = {}
                    audit_proctitle = timestampExtractor.getAuditProctitle(line)
                    if audit_proctitle is not None:
                        if audit_proctitle not in audit_proctitles[scenario_variant]:
                            try:
                                audit_proctitle_decoded = bytes.fromhex(audit_proctitle).decode('utf-8')
                            except:
                                # proctitle is not encoded
                                audit_proctitle_decoded = ""
                            audit_proctitles[scenario_variant][audit_proctitle] = [audit_proctitle_decoded, timestamp, timestamp, 0, 0, 1] # proctitle decoded, first seen timestamp, last seen timestamp, first seen during attack, attack count, normal count
                        else:
                            audit_proctitles[scenario_variant][audit_proctitle][2] = timestamp # update last seen timestamp
                            audit_proctitles[scenario_variant][audit_proctitle][5] += 1
        with open("logs.csv", "a") as logs_csv:
            logs_csv.write(scenario_variant_short + "," + log_path_out + ",NA,NA,NA," + keyword + ",1," + str(new_line) + ",NA," + str(timestamp.timestamp()) + "\n")

def filter_logs(line, timestamp, full_path, attack_times_list, scenario_variant_file, keyword, normal_logs, attacks_start):
    normal_start = attacks_start[scenario_variant_file] - timedelta(minutes=11)
    normal_end = attacks_start[scenario_variant_file] - timedelta(minutes=1)
    reduced_line = timestampExtractor.timestampRemove[keyword](line)
    if keyword in log_filter_options and log_filter_options[keyword] == "remove_digits":
        reduced_line = ''.join(c for c in line if not c.isdigit())
    if timestamp >= normal_start and timestamp < normal_end:
        normal_logs.add(reduced_line)
        return 0
    elif timestamp >= normal_end:
        if reduced_line in normal_logs:
            return 0
        else:
            return 1
    return 0

print("Process AttackMate logs...")
attack_times = {}

attack_output = {}
for root, dirs, files in os.walk(data_dir):
    dirs.sort()
    files.sort()
    for file in files:
        full_path = os.path.join(root, file)
        if full_path.endswith("/output.log") and "/attacker/" in full_path:
            scenario_variant = full_path[:full_path.index("/attacker/")] # select the part of the path describing the scenario, i.e., everything before /attacker/
            attack_output[scenario_variant] = {}
            with open(full_path) as filehandle:
                entire_log = ""
                for line in filehandle:
                    if entire_log != "" and re.search(multiline_start["/attacker/logs/output.log"], line):
                        # Line break point has been reached
                        timestamp = timestampExtractor.timestampExtractor["/attacker/logs/output.log"](entire_log)
                        output_cmd = timestampExtractor.getAttackMateOutputCommand(entire_log)
                        if output_cmd in attack_output[scenario_variant]:
                            attack_output[scenario_variant][output_cmd].append(timestamp)
                        else:
                            attack_output[scenario_variant][output_cmd] = [timestamp]
                        entire_log = ""
                    entire_log += line
                if entire_log != "":
                    timestamp = timestampExtractor.timestampExtractor["/attacker/logs/output.log"](entire_log)
                    output_cmd = timestampExtractor.getAttackMateOutputCommand(entire_log)
                    if output_cmd in attack_output[scenario_variant]:
                        attack_output[scenario_variant][output_cmd].append(timestamp)
                    else:
                        attack_output[scenario_variant][output_cmd] = [timestamp]

attacks_start = {}
event_id_counter = {}
event_id_info = {}
nodes = {}
edges = {}
variants = {}
seq_id_dict = {}
labels = {}
for root, dirs, files in os.walk(data_dir):
    dirs.sort()
    files.sort()
    for file in files:
        full_path = os.path.join(root, file)
        if full_path.endswith("/attackmate.json") and "/attacker/" in full_path:
            scenario_variant = full_path[:full_path.index("/attacker/")] # select the part of the path describing the scenario, i.e., everything before /attacker/
            scenario_variant_short = re.search(r".*/scenario_(.+)$", scenario_variant).group(1).strip("_")
            scenario_id = scenario_variant_short[0]
            variant_id = scenario_variant_short.replace(scenario_id, "").removeprefix("_")
            if scenario_id not in event_id_counter:
                event_id_counter[scenario_id] = {}
            if scenario_id not in event_id_info:
                event_id_info[scenario_id] = {}
            if scenario_id not in nodes:
                nodes[scenario_id] = {}
                edges[scenario_id] = set()
            if scenario_variant_short not in seq_id_dict:
                seq_id_dict[scenario_variant_short] = {}
            attack_times[scenario_variant] = []
            tactic_count = {}
            prev_viz_id = None
            cmd_alt = ""
            with open(full_path) as filehandle:
                for line in filehandle:
                    j = json.loads(line)
                    timestamp = timestampExtractor.timestampExtractor["/attackmate.json"](line)
                    if scenario_variant not in attacks_start:
                        attacks_start[scenario_variant] = timestamp
                    if j["type"] == "sleep" and len(attack_times[scenario_variant]) > 0:
                        # Sleep is used when attack manifestations occur even after the attack command has ended; thus, extend the previous attack interval
                        attack_times[scenario_variant][-1]["end"] += timedelta(seconds=float(j["parameters"]["seconds"]))
                    elif "parameters" in j and "metadata" in j["parameters"] and isinstance(j["parameters"]["metadata"], dict) and ("delayed_manifestation" in j["parameters"]["metadata"] or "description" in j["parameters"]["metadata"]) and "techniques" not in j["parameters"]["metadata"]:
                        # No attack information in metadata, do nothing on purpose
                        pass
                    elif "parameters" in j and "metadata" in j["parameters"] and j["parameters"]["metadata"] is not None: # and "action" not in j["parameters"]["metadata"]:
                        metadata = {}
                        if "techniques" not in j["parameters"]["metadata"]:
                            if "action" in j["parameters"]["metadata"]:
                                if j["cmd"] != "sleep" and j["cmd"] != "key" and j["cmd"] != "move" and j["cmd"] != "click" and "parameters" in j and "input" in j["parameters"] and j["parameters"]["input"] is not None:
                                    cmd_alt = j["parameters"]["input"]
                                elif j["cmd"] != "sleep" and j["cmd"] != "key" and j["cmd"] != "move" and j["cmd"] != "click":
                                    cmd_alt = j["cmd"]
                                continue
                            j["parameters"]["metadata"]["techniques"] = "Unknown"
                            j["parameters"]["metadata"]["tactics"] = "Unknown"
                            j["parameters"]["metadata"]["technique_name"] = "Unknown"
                            metadata["Unknown"] = {"tactics": ["Unknown"], "technique_name": "Unknown"}
                        else:
                            attackmate_technique_list = j["parameters"]["metadata"]["techniques"].split(",")
                            for attackmate_technique in attackmate_technique_list:
                                attackmate_technique = attackmate_technique.strip(" ")
                                if "." in attackmate_technique:
                                    # Name of sub-technique needs to be combined with name of technique
                                    technique_name = mitre_mapping[attackmate_technique.split(".")[0]]["name"] + ": " + mitre_mapping[attackmate_technique]["name"]
                                else:
                                    technique_name = mitre_mapping[attackmate_technique]["name"]
                                metadata[attackmate_technique] = {"tactics": mitre_mapping[attackmate_technique]["tactics"], "technique_name": technique_name}
                        # GET UNIQUE ID FOR EACH ATTACK STEP
                        j_clean = dict(j)
                        del j_clean["start-datetime"]
                        j_clean["metadata"] = metadata
                        if "metadata" in j_clean["parameters"]:
                            del j_clean["parameters"]["metadata"]
                        if "clear_cache" in j_clean["parameters"]:
                            del j_clean["parameters"]["clear_cache"]
                        if "write" in j_clean["parameters"]:
                            del j_clean["parameters"]["write"]
                        if "username" in j_clean["parameters"]:
                            del j_clean["parameters"]["username"]
                        if "password" in j_clean["parameters"]:
                            del j_clean["parameters"]["password"]
                        if "key_filename" in j_clean["parameters"]:
                            del j_clean["parameters"]["key_filename"]
                        if "end_str" in j_clean["parameters"]:
                            del j_clean["parameters"]["end_str"]
                        if "local_path" in j_clean["parameters"]:
                            del j_clean["parameters"]["local_path"]
                        if j_clean["cmd"].startswith("rm "):
                            j_clean["cmd"] = "rm" # Merge all rm commands
                        elif j_clean["cmd"] == "type":
                            j_clean["cmd"] = j_clean["parameters"]["input"]
                        else:
                            j_clean["cmd"] = j_clean["cmd"].removeprefix("sudo bash -c \"") # Avoid mismatch of 'command -v lsusb' and 'sudo bash -c "command -v lsusb"'
                            j_clean["cmd"] = j_clean["cmd"].removesuffix("\"")
                            j_clean["cmd"] = j_clean["cmd"].removeprefix("sudo ") # Avoid mismatch of all sudo and non sudo commands
                            j_clean["cmd"] = j_clean["cmd"].replace("/usr/bin/", "").replace("/bin/", "").replace("/opt/", "").replace("/root/", "") # Avoid mismatch of '/usr/bin/cat' and 'cat' and similar
                        j_clean["cmd"] = re.sub(r'[^a-zA-Z0-9]', '_', j_clean["cmd"])
                        j_hash = hash(json.dumps(j_clean, sort_keys=True))
                        if j_hash not in event_id_counter[scenario_id]:
                            if len(event_id_counter[scenario_id]) == 0:
                                event_id_counter[scenario_id][j_hash] = 1
                            else:
                                event_id_counter[scenario_id][j_hash] = max(event_id_counter[scenario_id].values()) + 1
                        event_id = event_id_counter[scenario_id][j_hash]
                        if event_id not in event_id_info[scenario_id]:
                            event_id_info[scenario_id][event_id] = {"variants": set([variant_id]), "j": j_clean, "metadata": metadata}
                        else:
                            event_id_info[scenario_id][event_id]["variants"].add(variant_id)
                        # Get unique sequence id for techniques that span multiple events
                        if len(attack_times[scenario_variant]) > 0:
                            prev_attackmate_techniques = attack_times[scenario_variant][-1]["metadata"]
                            # Get the techniques that have already occurred in the previous step
                            continuing_attackmate_techniques = set(metadata).intersection(set(prev_attackmate_techniques))
                            for attackmate_technique in continuing_attackmate_techniques:
                                seq_id_dict[scenario_variant_short][attackmate_technique][-1].append(str(event_id))
                            # Get the techniques that first occurred in this step (at least not directly before; could have occurred earlier)
                            new_attackmate_techniques = set(metadata).difference(set(prev_attackmate_techniques))
                            for attackmate_technique in new_attackmate_techniques:
                                if attackmate_technique not in seq_id_dict[scenario_variant_short]:
                                    seq_id_dict[scenario_variant_short][attackmate_technique] = [[str(event_id)]]
                                else:
                                    seq_id_dict[scenario_variant_short][attackmate_technique].append([str(event_id)])
                        else:
                            # First event in scenario; add event to every technique sequence
                            for attackmate_technique in metadata:
                                seq_id_dict[scenario_variant_short][attackmate_technique] = [[str(event_id)]]
                        # VISUALIZATION
                        # Add nodes
                        viz_id = str(event_id)
                        nodes[scenario_id][viz_id] = str(event_id) + ": " + str(j_clean["cmd"]) + "\n"
                        tactics_for_viz = set()
                        for attackmate_technique in metadata:
                            nodes[scenario_id][viz_id] += str(attackmate_technique) + ": " + metadata[attackmate_technique]["technique_name"] + "\n"
                            for tactic_for_viz in metadata[attackmate_technique]["tactics"]:
                                tactics_for_viz.add(tactic_for_viz)
                        nodes[scenario_id][viz_id] += str(tactics_for_viz) + "\n"
                        # Add scenario variant information
                        if scenario_id not in variants:
                            variants[scenario_id] = {}
                        if viz_id not in variants[scenario_id]:
                            variants[scenario_id][viz_id] = []
                        if variant_id not in variants[scenario_id][viz_id]:
                            variants[scenario_id][viz_id].append(variant_id)
                        # Add edges
                        if prev_viz_id is not None:
                            edges[scenario_id].add((prev_viz_id, viz_id))
                        prev_viz_id = viz_id
                        # FIND END TIME OF ATTACK STEP
                        earliest_end_timestamp = None
                        attackmate_cmd = j["cmd"].split("\n")[0]
                        if attackmate_cmd in attack_output[scenario_variant]:
                            for possible_end_timestamp in attack_output[scenario_variant][attackmate_cmd]:
                                if possible_end_timestamp >= timestamp - timedelta(seconds=1): # Need to subtract 1 second since timestamp may have float while end timestamp is rounded to full seconds
                                    if earliest_end_timestamp is None or possible_end_timestamp < earliest_end_timestamp:
                                        earliest_end_timestamp = possible_end_timestamp
                        else:
                            print("ERROR: Could not find command " + attackmate_cmd + " in attackmate output of " + scenario_variant + ": " + str(attack_output[scenario_variant]) + ". Aborting")
                            exit()
                        if earliest_end_timestamp is None:
                            print("ERROR: No end time for command " + attackmate_cmd + " at " + str(timestamp) + " found in attackmate output of " + scenario_variant + ": " + str(attack_output[scenario_variant]) + ". Aborting")
                            exit()
                        # Manually adapt attack time windows
                        if scenario_variant_short in fix_time_start and event_id in fix_time_start[scenario_variant_short]:
                            timestamp += timedelta(seconds=fix_time_start[scenario_variant_short][event_id])
                        if scenario_variant_short in fix_time_end and event_id in fix_time_end[scenario_variant_short]:
                            earliest_end_timestamp += timedelta(seconds=fix_time_end[scenario_variant_short][event_id])
                        attack_times[scenario_variant].append({"start": timestamp - timedelta(seconds=2), "end": earliest_end_timestamp + timedelta(seconds=4), "metadata": metadata, "full_path": full_path, "cmd": j_clean["cmd"].split(" ")[0], "event_id": str(event_id)})
                        label_key = str(scenario_variant_short) + "-" + str(event_id)
                        labels[label_key] = {"scenario_variant": scenario_variant_short, "event_id": str(event_id), "metadata": metadata, "full_path": full_path, "cmd": j_clean["cmd"].split(" ")[0], "attackmate": j, "cmd_alt": cmd_alt}
                    if j["cmd"] != "sleep" and j["cmd"] != "key" and j["cmd"] != "move" and j["cmd"] != "click" and "parameters" in j and "input" in j["parameters"] and j["parameters"]["input"] is not None:
                        cmd_alt = j["parameters"]["input"]
                    elif j["cmd"] != "sleep" and j["cmd"] != "key" and j["cmd"] != "move" and j["cmd"] != "click":
                        cmd_alt = j["cmd"]

# Deduplicate list of event sequences per technique
seq_id_dict_new = {}
for scenario_variant_short, seq_id_dict_entry in seq_id_dict.items():
    for attackmate_technique, event_id_list in seq_id_dict_entry.items():
        if scenario_variant_short not in seq_id_dict_new:
            seq_id_dict_new[scenario_variant_short] = {}
        seq_id_dict_new[scenario_variant_short][attackmate_technique] = [list(t) for t in set([tuple(lst) for lst in event_id_list])]
seq_id_dict = seq_id_dict_new

if print_state_charts:
    for scenario_id in nodes:
        dot = Digraph(comment="Commands State Diagram") #, format='png')
        dot.attr(rankdir='TB')
        for viz_id, label in nodes[scenario_id].items():
            label += ', '.join(variants[scenario_id][viz_id])
            dot.node(str(viz_id), label, shape='box', style='rounded')
        for src, dst in edges[scenario_id]:
            dot.edge(str(src), str(dst))
        dot.render("state_diagrams/state_diagram_scenario_" + str(scenario_id), format="png")
        dot.render("state_diagrams/state_diagram_scenario_" + str(scenario_id), format="pdf")

if print_event_id_info:
    for scenario_id, event_id_dict in event_id_info.items():
        print("Scenario " + str(scenario_id))
        if False:
            # Sort by technique number for easier comparison
            event_id_dict = dict(sorted(event_id_dict.items(), key=lambda item: next(iter(item[1].get('metadata', {})), '')))
        for event_id, event_id_inner_dict in event_id_dict.items():
            techniques = ""
            tactics = []
            for technique, technique_dict in event_id_inner_dict["metadata"].items():
                techniques += technique + ", "
                for inner_tactic in technique_dict["tactics"]:
                    if inner_tactic not in tactics:
                        tactics.append(inner_tactic)
            techniques = techniques[:-2]
            tactics = ", ".join(tactics)
            print(str(event_id) + " & " + tactics + " & " + techniques + " & " + str(re.sub(r'[^a-zA-Z0-9 ]', '', event_id_inner_dict["j"]["cmd"])) + " & " + str(sorted(event_id_inner_dict["variants"])) + " &  \\\\ \\hline")

with open("labels.json", "w+") as labels_fh:
    labels_fh.write(json.dumps(labels))

with open("attack_times.csv", "w") as attack_times_fh:
    attack_times_fh.write("scenario;tactics;techniques;technique_names;event_id;cmd;start;end\n")
    for scenario_variant, attack_times_list in attack_times.items():
        for attack_time_dict in attack_times_list:
            if "metadata" in attack_time_dict and attack_time_dict["metadata"] is not None:
                tactics = ""
                technique_names = ""
                for technique in attack_time_dict["metadata"]:
                    tactics += "_".join(attack_time_dict["metadata"][technique]["tactics"])
                attack_times_fh.write(re.search(r".*/scenario_(.+)$", scenario_variant).group(1).strip("_") + ";" + tactics + ";" + "_".join(attack_time_dict["metadata"]) + ";NA;" + attack_time_dict["event_id"] + ";" + re.sub(r'[^a-zA-Z0-9]', '_', attack_time_dict["cmd"]) + ";" + str(attack_time_dict["start"].timestamp()) + ";" + str(attack_time_dict["end"].timestamp()) + "\n")

print("Clean output directories")

if os.path.exists(manifestations_dir):
    try:
        # Delete the manifestations dir to avoid that any artifacts from previous runs remain
        print("Remove " + manifestations_dir + " directory...")
        shutil.rmtree(manifestations_dir)
        print("Done.")
    except Exception as e:
        print(f"Error deleting folder: {e}")
if os.path.exists(seq_dir):
    try:
        # Delete the seq dir to avoid that any artifacts from previous runs remain
        print("Remove " + seq_dir + " directory...")
        shutil.rmtree(seq_dir)
        print("Done.")
    except Exception as e:
        print(f"Error deleting folder: {e}")
if os.path.exists(event_dir):
    try:
        # Delete the event dir to avoid that any artifacts from previous runs remain
        print("Remove " + event_dir + " directory...")
        shutil.rmtree(event_dir)
        print("Done.")
    except Exception as e:
        print(f"Error deleting folder: {e}")
if os.path.exists(manifestations_raw_dir):
    try:
        # Delete the manifestations raw dir to avoid that any artifacts from previous runs remain
        print("Remove " + manifestations_raw_dir + " directory...")
        shutil.rmtree(manifestations_raw_dir)
        print("Done.")
    except Exception as e:
        print(f"Error deleting folder: {e}")
if os.path.exists(seq_raw_dir):
    try:
        # Delete the seq dir to avoid that any artifacts from previous runs remain
        print("Remove " + seq_raw_dir + " directory...")
        shutil.rmtree(seq_raw_dir)
        print("Done.")
    except Exception as e:
        print(f"Error deleting folder: {e}")
if os.path.exists(event_raw_dir):
    try:
        # Delete the event dir to avoid that any artifacts from previous runs remain
        print("Remove " + event_raw_dir + " directory...")
        shutil.rmtree(event_raw_dir)
        print("Done.")
    except Exception as e:
        print(f"Error deleting folder: {e}")

print("Process logs for filtering...")

normal_logs_all = {}
if filter_logs_all_scenarios:
    for root, dirs, files in os.walk(data_dir):
        dirs.sort()
        files.sort()
        for file in files:
            full_path = os.path.join(root, file)
            if os.path.getsize(full_path) == 0:
                # Skip empty files
                continue
            if any(keyword in full_path for keyword in blacklist) or any(keyword not in full_path for keyword in whitelist):
                continue
            scenario_variant_file = None
            for scenario_variant in attack_times:
                if full_path.startswith(scenario_variant):
                    scenario_variant_file = scenario_variant
            keyword_match = set()
            for keyword in timestampExtractor.timestampExtractor:
                if keyword in full_path:
                    keyword_match.add(keyword)
                    if keyword not in normal_logs_all:
                        normal_logs_all[keyword] = set()
                    if len(keyword_match) > 1:
                        print("ERROR: Multiple matching keywords found for " + full_path + ": " + str(keyword_match))
                        exit()
                    with open_log_file(full_path) as filehandle:
                        if keyword == "/audit/audit.log":
                            audit_by_id = {}
                            entire_log = ""
                            for line in filehandle:
                                audit_id = timestampExtractor.idExtractor[keyword](line)
                                if audit_id not in audit_by_id:
                                    audit_by_id[audit_id] = line
                                else:
                                    audit_by_id[audit_id] += line
                            for _, entire_log in audit_by_id.items():
                                    timestamp = timestampExtractor.timestampExtractor[keyword](entire_log)
                                    new_line = filter_logs(entire_log, timestamp, full_path, attack_times, scenario_variant_file, keyword, normal_logs_all[keyword], attacks_start)
                        elif keyword in multiline_end:
                            entire_log = ""
                            for line in filehandle:
                                entire_log += line
                                if not re.search(multiline_end[keyword], entire_log):
                                    # Line break point has not been reached yet
                                    continue
                                # Line break point has been reached
                                timestamp = timestampExtractor.timestampExtractor[keyword](entire_log)
                                new_line = filter_logs(entire_log, timestamp, full_path, attack_times, scenario_variant_file, keyword, normal_logs_all[keyword], attacks_start)
                                entire_log = ""
                        elif keyword in multiline_start:
                            entire_log = ""
                            for line in filehandle:
                                if entire_log != "" and re.search(multiline_start[keyword], line):
                                    # Line break point has been reached
                                    timestamp = timestampExtractor.timestampExtractor[keyword](entire_log)
                                    new_line = filter_logs(entire_log, timestamp, full_path, attack_times, scenario_variant_file, keyword, normal_logs_all[keyword], attacks_start)
                                    entire_log = ""
                                entire_log += line
                            if entire_log != "":
                                timestamp = timestampExtractor.timestampExtractor[keyword](entire_log)
                                new_line = filter_logs(entire_log, timestamp, full_path, attack_times, scenario_variant_file, keyword, normal_logs_all[keyword], attacks_start)
                        else:
                            prev_timestamp = None
                            for line in filehandle:
                                try:
                                    timestamp = timestampExtractor.timestampExtractor[keyword](line)
                                except ValueError as e:
                                    if detailed_output:
                                        print(f"  Caught a ValueError: {e}")
                                    # In case that one of the lines has no timestamp, use the timestamp from the previous line
                                    timestamp = prev_timestamp
                                new_line = filter_logs(line, timestamp, full_path, attack_times, scenario_variant_file, keyword, normal_logs_all[keyword], attacks_start)
                                prev_timestamp = timestamp
            if len(keyword_match) == 0:
                print("ERROR: No parser found for " + full_path)
                i = 0
                with open_log_file(full_path) as filehandle:
                    for line in filehandle:
                        i += 1
                        if i > 5:
                            break
                        print("  " + line.strip("\n\r"))
                exit()

print("Write filtered logs to disk...")

for keyword, normal_logs in normal_logs_all.items():
    os.makedirs(os.path.dirname("filtered_logs/" + keyword), exist_ok = True)
    with open("filtered_logs/" + keyword, "w+") as filtered_fh:
        for log in normal_logs:
            if log.endswith("\n"):
                filtered_fh.write(log)
            else:
                filtered_fh.write(log + "\n")

print("Write log summary to disk...")

with open("logs.csv", "w+") as logs_csv:
    logs_csv.write("scenario,logfile,tactics,technique,subtechnique,file_type,id,new,cmd,timestamp\n")

print("Write logs to disk...")

num_files_processed = 0
for root, dirs, files in os.walk(data_dir):
    dirs.sort()
    files.sort()
    for file in files:
        full_path = os.path.join(root, file)
        if os.path.getsize(full_path) == 0:
            # Skip empty files
            continue
        if any(keyword in full_path for keyword in blacklist) or any(keyword not in full_path for keyword in whitelist):
            continue
        num_files_processed += 1
        if detailed_output:
            print(full_path)
        scenario_variant_file = None
        for scenario_variant in attack_times:
            if full_path.startswith(scenario_variant):
                scenario_variant_file = scenario_variant
        keyword_match = set()
        for keyword in timestampExtractor.timestampExtractor:
            if keyword in full_path:
                keyword_match.add(keyword)
                if len(keyword_match) > 1:
                    print("ERROR: Multiple matching keywords found for " + full_path + ": " + str(keyword_match))
                    exit()
                with open_log_file(full_path) as filehandle:
                    if keyword == "/audit/audit.log":
                        audit_by_id = {}
                        entire_log = ""
                        for line in filehandle:
                            audit_id = timestampExtractor.idExtractor[keyword](line)
                            if audit_id not in audit_by_id:
                                audit_by_id[audit_id] = line
                            else:
                                audit_by_id[audit_id] += line
                        for _, entire_log in audit_by_id.items():
                                timestamp = timestampExtractor.timestampExtractor[keyword](entire_log)
                                new_line = filter_logs(entire_log, timestamp, full_path, attack_times, scenario_variant_file, keyword, normal_logs_all[keyword], attacks_start)
                                if new_line == 1 and keyword in log_filter_keywords:
                                    for log_filter_keyword in log_filter_keywords[keyword]:
                                        if log_filter_keyword in entire_log:
                                            new_line = 0
                                            break
                                write_to_file(entire_log, timestamp, full_path, attack_times, scenario_variant_file, keyword, new_line, seq_id_dict)
                    elif keyword in multiline_end:
                        entire_log = ""
                        for line in filehandle:
                            entire_log += line
                            if not re.search(multiline_end[keyword], entire_log):
                                # Line break point has not been reached yet
                                continue
                            # Line break point has been reached
                            timestamp = timestampExtractor.timestampExtractor[keyword](entire_log)
                            new_line = filter_logs(entire_log, timestamp, full_path, attack_times, scenario_variant_file, keyword, normal_logs_all[keyword], attacks_start)
                            if new_line == 1 and keyword in log_filter_keywords:
                                for log_filter_keyword in log_filter_keywords[keyword]:
                                    if log_filter_keyword in entire_log:
                                        new_line = 0
                                        break
                            write_to_file(entire_log, timestamp, full_path, attack_times, scenario_variant_file, keyword, new_line, seq_id_dict)
                            entire_log = ""
                    elif keyword in multiline_start:
                        entire_log = ""
                        for line in filehandle:
                            if entire_log != "" and re.search(multiline_start[keyword], line):
                                # Line break point has been reached
                                timestamp = timestampExtractor.timestampExtractor[keyword](entire_log)
                                new_line = filter_logs(entire_log, timestamp, full_path, attack_times, scenario_variant_file, keyword, normal_logs_all[keyword], attacks_start)
                                if new_line == 1 and keyword in log_filter_keywords:
                                    for log_filter_keyword in log_filter_keywords[keyword]:
                                        if log_filter_keyword in entire_log:
                                            new_line = 0
                                            break
                                write_to_file(entire_log, timestamp, full_path, attack_times, scenario_variant_file, keyword, new_line, seq_id_dict)
                                entire_log = ""
                            entire_log += line
                        if entire_log != "":
                            timestamp = timestampExtractor.timestampExtractor[keyword](entire_log)
                            new_line = filter_logs(entire_log, timestamp, full_path, attack_times, scenario_variant_file, keyword, normal_logs_all[keyword], attacks_start)
                            if new_line == 1 and keyword in log_filter_keywords:
                                for log_filter_keyword in log_filter_keywords[keyword]:
                                    if log_filter_keyword in entire_log:
                                        new_line = 0
                                        break
                            write_to_file(entire_log, timestamp, full_path, attack_times, scenario_variant_file, keyword, new_line, seq_id_dict)
                    else:
                        prev_timestamp = None
                        for line in filehandle:
                            try:
                                timestamp = timestampExtractor.timestampExtractor[keyword](line)
                            except ValueError as e:
                                if detailed_output:
                                    print(f"  Caught a ValueError: {e}")
                                # In case that one of the lines has no timestamp, use the timestamp from the previous line
                                timestamp = prev_timestamp
                            if "scenario_7" in full_path and keyword == "/syslog":
                                timestamp = timestamp.replace(year=2026) # Unfortunately, since syslog has no year, we need to manually overwrite the year here since scenario 7 is the only one recorded in 2026
                            new_line = filter_logs(line, timestamp, full_path, attack_times, scenario_variant_file, keyword, normal_logs_all[keyword], attacks_start)
                            if new_line == 1 and keyword in log_filter_keywords:
                                for log_filter_keyword in log_filter_keywords[keyword]:
                                    if log_filter_keyword in line:
                                        new_line = 0
                                        break
                            write_to_file(line, timestamp, full_path, attack_times, scenario_variant_file, keyword, new_line, seq_id_dict)
                            prev_timestamp = timestamp
        if len(keyword_match) == 0:
            print("ERROR: No parser found for " + full_path)
            i = 0
            with open_log_file(full_path) as filehandle:
                for line in filehandle:
                    i += 1
                    if i > 5:
                        break
                    print("  " + line.strip("\n\r"))
            exit()

print(str(num_files_processed) + " files processed.")

if len(audit_proctitles) > 0:
    print("Analyzing audit processes...")
    for scenario_variant, audit_proctitles_dict in audit_proctitles.items():
        print("Scenario-variant" + str(scenario_variant))
        for audit_proctitle, audit_proctitle_tuple in audit_proctitles_dict.items():
            audit_proctitle_decoded, first_seen, last_seen, new, att_count, norm_count = audit_proctitle_tuple
            if (last_seen - first_seen).total_seconds() < 30 or (att_count + norm_count) < 10:
                continue
            if new == 1:
                prefix = "!!!"
            else:
                prefix = ""
            if audit_proctitle_decoded != "":
                print(prefix + " " + audit_proctitle_decoded)
            print(prefix + " " + audit_proctitle)
            print(prefix + " " + str(first_seen) + " - " + str(last_seen) + ": " + str(att_count) + "/" + str(norm_count) + "\n")

print("Done.")
