all: injector

injector: injector.o
	gcc $< -o $@

injector.o: injector.c payloads.h
	gcc -c $< -o $@

payloads.h: thread_creator_32.bin thread_creator_64.bin
	@echo '#ifndef PAYLOADS_H' > payloads.h
	@echo '#define PAYLOADS_H' >> payloads.h
	@echo >> payloads.h
	xxd -i thread_creator_32.bin >> payloads.h
	@echo -e '\n#ifdef __x86_64__' >> payloads.h
	xxd -i thread_creator_64.bin >> payloads.h
	@echo -e '#endif\n' >> payloads.h
	@echo '#endif' >> payloads.h

thread_creator_32.bin: thread_creator_32.o
	objcopy -O binary $< $@

thread_creator_64.bin: thread_creator_64.o
	objcopy -O binary $< $@

thread_creator_32.o: thread_creator_32.s
	as --32 $< -o $@

thread_creator_64.o: thread_creator_64.s
	as --64 $< -o $@
clean:
	@rm -f injector payloads.h *.o *.bin
