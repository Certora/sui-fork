set -e
sui move build --test
certoraSuiProver.py Bridge.conf
