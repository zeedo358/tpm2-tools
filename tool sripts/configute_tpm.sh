#!/usr/bin/env bash
sudo tpm2_createprimary -c primary.ctx
sudo tpm2_create -C primary.ctx -Grsa2048 -u key.pub -r key.priv
sudo tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
