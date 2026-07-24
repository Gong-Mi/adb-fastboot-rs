# aidl-rs syntax scope

`aidl-rs` is a small parser/code generator, not a replacement for Android 17's
`aidl` compiler. The supported subset currently includes packages/imports,
annotations represented as name/value strings, interfaces and `oneway`, method
directions and explicit IDs, structured parcelables with fields/default literals,
enums, unions, arrays, and the `List`/`Map` generic shapes used by the Rust
generator.

The following Android 17 syntax is intentionally **unsupported or only partially
represented**:

* unstructured parcelable headers (`ndk_header` and `rust_type`), and generic
declaration type parameters;
* interface declarations without a body are not represented as a distinct
forward declaration, and interface inheritance is not an Android 17 grammar
feature (the AST's legacy `extends` field is not generated);
* full constant expressions (operators, parenthesized expressions, arrays,
references, booleans, and enum references) are not evaluated; only a single
literal/identifier is retained;
* fixed-size arrays, nested-array restrictions, and AIDL type validation are not
enforced;
* annotation semantics, stability/versioning, `@VintfStability`,
`@JavaOnlyStableParcelable`, and backend-specific validation are not implemented;
* generated Rust is a lightweight trait/data model and does not implement
Android Binder parceling, metadata, API dumps, or backend-compatible stubs.

Transaction constants follow Android's convention: the generated value is
`FIRST_CALL_TRANSACTION + method_id`, with implicit method IDs assigned from 0
in source order.
