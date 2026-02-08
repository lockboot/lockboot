.PRECIOUS: %.key %.crt %.cer %.guid

all: PK.cer KEK.cer db.cer

%.crt:
	openssl req -newkey rsa:4096 -nodes -keyout "$@.key" -new -x509 -sha256 -days 3650 -subj "/CN=Lock.Boot/" -out "$@"
	#openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$@.key" -new -x509 -sha256 -days 3650 -subj "/CN=Lock.Boot/" -out "$@"

%.cer: %.crt %.guid
	openssl x509 -outform DER -in "$<" -out "$@"

%.guid:
	uuidgen > "$@"

clean:
	rm -f *.crt *.key *.cer *.guid
