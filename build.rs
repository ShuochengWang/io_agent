extern crate cc;

fn main() {
    cc::Build::new()
        .file("src/io_uring.c")
        .flag("-luring")
        .compile("io_uring.a");
}
