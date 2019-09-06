#! /bin/bash

. ${DIR}/tun_aesgcm_defs.sh

CRYPTO_DEV=${CRYPTO_DEV:-'--vdev="crypto_aesni_mb0"'}

SGW_CFG_XPRM='type cpu-crypto'
