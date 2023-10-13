#!/bin/bash

echo "set-option -g default-shell /bin/bash" > ~/.tmux.conf
python3.9 -m venv .venv
source .venv/bin/activate
pip install prowler