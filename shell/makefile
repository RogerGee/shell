################################################################################
# Makefile for cs356/shell #####################################################
################################################################################
PHONY: clean

# set flags for master rule
ifeq ($(MAKECMDGOALS),debug)
MAKE_DEBUG = yes
else
MAKE_ALL = yes
endif

# set options
OUT = -o
ifdef MAKE_DEBUG
COMPILE = gcc -g -c -Wall -Werror -Wextra -Wshadow -pedantic-errors -Wfatal-errors -Wno-unused-variable -std=gnu99
LINK = gcc
PROGRAM_NAME = rogershell-debug
OBJDIR = dobj
endif

ifdef MAKE_ALL
COMPILE = gcc -c -Wall -Werror -Wextra -Wshadow -pedantic-errors -Wfatal-errors -Wno-unused-variable -std=gnu99
LINK = gcc -s
PROGRAM_NAME = rogershell
OBJDIR = obj
endif

# headers
PROC_H = proc.h

# object code files
OBJECTS = shell.o proc.o
OBJECTS := $(addprefix $(OBJDIR)/,$(OBJECTS))

# rules
all: $(PROGRAM_NAME)
debug: $(PROGRAM_NAME)

$(PROGRAM_NAME): $(OBJDIR) $(OBJECTS)
	$(LINK) $(OUT)$(PROGRAM_NAME) $(OBJECTS)

$(OBJDIR)/shell.o: shell.c $(PROC_H)
	$(COMPILE) $(OUT)$(OBJDIR)/shell.o shell.c
$(OBJDIR)/proc.o: proc.c $(PROC_H)
	$(COMPILE) $(OUT)$(OBJDIR)/proc.o proc.c
$(OBJDIR):
	mkdir $(OBJDIR)
