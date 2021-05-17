NAME ?= xordump
OUT = build

BIN_DIR := $(GOPATH)/bin
GODONUT := $(BIN_DIR)/go-donut

all: windows shellcode

windows:
	GOOS=windows go build \
	     -trimpath \
	     -buildmode=pie \
	     -ldflags="-s -w -H windowsgui" \
	     -o build/${NAME}.exe \
	     main.go

shellcode: $(GODONUT) windows
	${GODONUT} --arch x64 --verbose --out ${OUT}/${NAME}.bin --in ${OUT}/${NAME}.exe

release: all
	@tar caf ${NAME}.tar.gz ${OUT}
	@rm -rf ${OUT}

clean:
	rm -rf ${OUT} ${NAME}*

$(GODONUT):
	go get -u github.com/Binject/go-donut
