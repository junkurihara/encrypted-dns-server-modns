#! /usr/bin/env bash

sleep 300

for service in encrypted-dns; do
    sv check "$service" || sv force-restart "$service"
done
