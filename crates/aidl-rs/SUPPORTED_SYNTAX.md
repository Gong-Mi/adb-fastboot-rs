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
* constant expressions are parsed with AIDL's unary/binary operator precedence
  and retained as canonical strings, but are not evaluated or type-checked;
  array literals, references, booleans, and enum references therefore remain
  representation-only;
* fixed-size arrays and nested-array restrictions are not enforced; the parser
  does enforce the supported generic shapes (`List<T>` and raw or `Map<K,V>`) and
  rejects generic arguments on scalar/custom types;
* annotation semantics, stability/versioning, `@VintfStability`,
`@JavaOnlyStableParcelable`, and backend-specific validation are not implemented;
* generated Rust is a lightweight trait/data model and does not implement
Android Binder parceling, metadata, API dumps, or backend-compatible stubs.

Transaction constants follow Android's convention: the generated value is
`FIRST_CALL_TRANSACTION + method_id`, with implicit method IDs assigned from 0
in source order.

## AOSP Android 17 comparison

The validation slice follows the Android 17 AOSP `system/tools/aidl` sources:

* `aidl_language.cpp` `AidlTypeSpecifier::CheckValid` (Android 17 branch,
  around lines 750-825) validates `List` arity 1 and `Map` arity 0 or 2.
* The AOSP AIDL language reference defines constant-expression precedence as
  `||`, `&&`, `|`, `^`, `&`, equality, relational, shifts, then arithmetic;
  this parser accepts that grammar and retains the expression instead of
  evaluating it.

This remains parser/type construction only. It does not implement AOSP symbol
resolution, constant type compatibility/evaluation, or Binder backend output.
