TARGET_DUMP=regfdump
OBJ_DUMP=regfdump.o rbtree.o oobmsg.o regf_cmn.o

TARGET_WALK=regfwalk
OBJ_WALK=regfwalk.o rbtree.o oobmsg.o regf_cmn.o

TARGET_TREE=regftree
OBJ_TREE=regftree.o rbtree.o oobmsg.o regf_cmn.o

CFLAGS += -Wall -g

UNAME_S=$(shell uname -s)

ifeq ($(UNAME_S),FreeBSD)
	CFLAGS +=-I/usr/local/include
	LDFLAGS +=-L/usr/local/lib -liconv
endif

PREFIX?=/usr/local

.PHONY: all install clean

all: $(TARGET_DUMP) $(TARGET_WALK) $(TARGET_TREE)

$(TARGET_DUMP): $(OBJ_DUMP)

$(TARGET_WALK): $(OBJ_WALK)

$(TARGET_TREE): $(OBJ_TREE)

install: all
	test -n "$(PREFIX)" && (test -d "$(PREFIX)" || mkdir -p "$(PREFIX)")
	test -d "$(PREFIX)/bin" || mkdir -p "$(PREFIX)/bin"
	install -m 0755 $(TARGET_DUMP) "$(PREFIX)/bin"
	install -m 0755 $(TARGET_WALK) "$(PREFIX)/bin"
	install -m 0755 $(TARGET_TREE) "$(PREFIX)/bin"

clean:
	rm -rf $(TARGET_DUMP) $(OBJ_DUMP)
	rm -rf $(TARGET_WALK) $(OBJ_WALK)
	rm -rf $(TARGET_TREE) $(OBJ_TREE)
