#!/bin/sh
# this commands require root permissions
tpm2_createprimary -c primary.ctx
tpm2_create -C primary.ctx -Grsa2048 -u key.pub -r key.priv
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
