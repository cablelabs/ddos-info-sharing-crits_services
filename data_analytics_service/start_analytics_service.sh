#!/usr/bin/env bash

. ./Paths.property
PYTHONPATH=${pythonpath} nohup python -W ignore start_analytics_service.py &