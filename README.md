This directory contains a sample script that allows you to connect to a Checkpoint Management Server and retrieve the information needed by Batfish.

The script makes the following assumptions, so you will need to edit/adapt it to fit your needs:

1) There is a single user or service account that has access to all devices.
2) Ansible vault is used to store the device credentials. The format of the data in the vault is as follows:
```yaml
svc_account_user: username
svc_account_password: password
```
3) Inventory file is a valid Ansible inventory in YAML format. Example:
```yaml
all:
  children:
    checkpoint_mgmt:
      vars:
        ansible_connection: local
        device_os: checkpoint_mgmt
      hosts:
        dummy01: null
```
4) You have DNS entries for the devices listed in your inventory. The script does NOT handle any sub-options under the host entries, such as `ansible_host`.

To see all the script options, run:
```bash
python3 collect_checkpoint_management_data.py -h
```

To run the script these are the mandatory options you will need to provide:
```bash
python3 collect_checkpoint_management_data.py --inventory <your inventory> \
    --output_dir <directory where the data should be written> \
    --vault <path to the Ansible vault used to store credentials> \
    --vault-password-file <path to file that has Ansible vault password>
```

The data that is written to the specified output directory needs to be put in the `checkpoint_management` sub-folder of the snapshot you plan to upload to Batfish.