IDIR = ./include
ODIR = ./obj
LDIR = ./lib

LIBS=-lm -l json -l pthread
CC=gcc
CFLAGS=-I${IDIR}
_DEPS = main.h common.h listener.h
_OBJ = main.o common.o listener.o

DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))
OBJ  = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

agent: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ 
