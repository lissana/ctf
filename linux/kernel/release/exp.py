import base64

print("rm exp.64")
print("touch exp.64")
x=open("exp.gz","rb").read()
f64 = base64.b64encode(x)
chunkcount = len(f64) / 64
for a in range(0, int(chunkcount)):
    print("echo " + f64[a*64:(a+1)*64].decode() + " >> exp.64")

if chunkcount % 1 > 0:
    print("echo " + f64[int(chunkcount)*64:].decode() + " >> exp.64")

print("base64 -d exp.64 | gzip -d > exp")
print("chmod +x exp")
print("./exp")
