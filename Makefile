ifeq ($(shell uname),Darwin)
    LDFLAGS := -Wl,-dead_strip
else
    LDFLAGS := -Wl,--gc-sections -lpthread -ldl -luring
endif

all: target/io_agent
	target/io_agent

target:
	mkdir -p $@

# target/io_agent: target/main.o target/debug/libio_agent.a
# 	$(CC) -luring -o $@ $^ $(LDFLAGS)
target/io_agent: target/main.o target/release/libio_agent.a
	$(CC) -luring -o $@ $^ $(LDFLAGS)

target/debug/libio_agent.a: src/lib.rs Cargo.toml
	cargo build

target/release/libio_agent.a: src/lib.rs Cargo.toml
	cargo build --release

target/main.o: src/main.c | target
	$(CC) -o $@ -c $<

clean:
	rm -rf target