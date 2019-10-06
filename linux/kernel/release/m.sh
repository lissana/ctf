rm exp.gz
rm exp
dietlibc-0.34/bin-x86_64/diet gcc exp.c -o exp
gzip -c exp > exp.gz
python exp.py
