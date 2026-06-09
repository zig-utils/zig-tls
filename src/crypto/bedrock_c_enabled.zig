//! Set by build.zig (`-Dbedrock-c-mul-base=true`) or `build_options.zig` when testing.
pub const enabled = @import("build_options").bedrock_c_mul_base;
