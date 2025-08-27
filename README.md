# Attack Simulation & Threat Detection  

## 📌 Project Overview  
This project involved simulating different types of cyber attacks to evaluate detection and response capabilities.  
The goal was to perform *controlled attack simulations* on endpoints and the network, then use *Wazuh SIEM and IDS* to detect malicious activities in real-time.  

---

## 🚀 Tools & Technologies  
- *Kali Linux* → For attack simulation (phishing, credential harvesting, brute force)  
- *Metasploit Framework* → Exploitation and payload generation  
- *Wazuh SIEM* → For centralized log collection and monitoring  
- *Snort / Suricata IDS* → Network intrusion detection  
- *Windows / Ubuntu Endpoints* → Targets for simulated attacks  

---

## 🔧 Attack Scenarios & Implementation Steps  
1. *Phishing Attack Simulation*  
   - Created a phishing email with a malicious attachment  
   - Sent it to a controlled test user  
   - Verified detection in Wazuh through suspicious process creation alerts  

2. *Brute Force Attack*  
   - Used Hydra to attempt SSH brute-force on Ubuntu endpoint  
   - Monitored Wazuh and Snort logs for repeated login failures  
   - Alert triggered for brute-force detection  

3. *Credential Theft*  
   - Simulated browser credential harvesting using keylogger and mimikatz  
   - Endpoint security and Wazuh agents detected suspicious process injection  

4. *Malware Execution*  
   - Delivered a test payload (reverse shell) using Metasploit  
   - Verified that endpoint agent detected new process creation and outbound connection  
   - Snort IDS flagged malicious traffic  

---

## 📊 Results  
- All simulated attacks were detected by Wazuh and IDS rules  
- Alert correlation helped identify *attack timeline*  
- Demonstrated the importance of endpoint + network monitoring together  
- Proved capability to respond to real-world attack vectors  

---

## 📂 Repository Structure
