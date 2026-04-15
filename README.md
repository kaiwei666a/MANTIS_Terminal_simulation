# MANTIS-terminal-simulation  


 
1) Generate an RSA host key

Run in the folder that contains Terminal_simulation.py:

```
ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N "" -C "honeypot local test key"

chmod 600 ssh_host_rsa_key
```




2) Run the simulation
If you run directly locally, enter in the terminal:` $env:OPENAI_API_KEY="openai key"`

And set system_log

Then run:   `python Terminal_simulation.py`

SFTP/SCP upload notes:

- Terminal simulation SSH/SFTP port is `2222` (from `Terminal_simulation.py`).
- Docker `atmoz/sftp` test container in this repo is mapped to host port `8022`.
- For `atmoz/sftp`, upload to `/upload/...` (not `/test.txt` and not `/home/sftpuser/...`).
- For terminal simulation (`2222`), uploaded files are staged under local `scp_root/` and then copied into
  `DOCKER_UPLOAD_CONTAINER` at `DOCKER_UPLOAD_PATH` (defaults: `terminal_sftp` and `/home/sftpuser/upload`).
- Upload security controls:
  - SHA-256 + AV scan results are appended to `upload_audit.jsonl`.
  - Uploaded files are forced to non-executable permissions (`0644`) locally and in Docker.
  - If scanner reports infection, the file is moved to `scp_root/_quarantine` and is not copied to Docker.

4) Quick SSH test (from same machine)
```
ssh root@127.0.0.1
```


> **Ubuntu note:** If you run this on Ubuntu, please start the simulation with `sudo` to avoid permission/binding issues (e.g., opening privileged ports).
> 
> **External access:** For connections from outside your local machine/network, deploy the service on a public host with a public IP and ensure the SSH port is exposed in your firewall/security group.



## Data

The dataset for this project is publicly available on Hugging Face:

**Hugging Face:** [your-link-here]

This dataset contains terminal interaction data designed for training and evaluating high-interaction terminal simulation systems, including multi-turn command-response behaviors and state-consistent environment interactions.
