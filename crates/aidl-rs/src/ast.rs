use std::fmt;

/// Represents a parsed AIDL file containing package, imports, and declarations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AidlFile {
    pub package: Option<String>,
    pub imports: Vec<String>,
    pub decls: Vec<AidlDecl>,
}

/// Top-level definition inside an AIDL file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AidlDecl {
    Interface(AidlInterface),
    Parcelable(AidlParcelable),
    Enum(AidlEnum),
    Union(AidlUnion),
}

/// AIDL Interface definition (`interface IService { ... }`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AidlInterface {
    pub annotations: Vec<Annotation>,
    pub is_oneway: bool,
    pub name: String,
    pub extends: Option<String>,
    pub methods: Vec<AidlMethod>,
    pub constants: Vec<AidlConstant>,
}

/// AIDL Parcelable definition (`parcelable Foo { ... }`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AidlParcelable {
    pub annotations: Vec<Annotation>,
    pub name: String,
    pub cpp_header: Option<String>,
    pub fields: Vec<AidlField>,
}

/// AIDL Enum definition (`enum Status { OK = 0, ERROR = 1 }`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AidlEnum {
    pub annotations: Vec<Annotation>,
    pub name: String,
    pub backing_type: Option<AidlType>,
    pub variants: Vec<EnumVariant>,
}

/// AIDL Union definition (`union Data { int num; String text; }`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AidlUnion {
    pub annotations: Vec<Annotation>,
    pub name: String,
    pub fields: Vec<AidlField>,
}

/// Enum variant (`VARIANT_NAME = value`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumVariant {
    pub name: String,
    pub value: Option<String>,
}

/// Method in an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AidlMethod {
    pub annotations: Vec<Annotation>,
    pub is_oneway: bool,
    pub return_type: AidlType,
    pub name: String,
    pub args: Vec<AidlArg>,
    pub id: Option<u32>,
}

/// Parameter in a method signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AidlArg {
    pub annotations: Vec<Annotation>,
    pub direction: Option<Direction>,
    pub ty: AidlType,
    pub name: String,
}

/// Direction tags for method parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
    InOut,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::In => write!(f, "in"),
            Direction::Out => write!(f, "out"),
            Direction::InOut => write!(f, "inout"),
        }
    }
}

/// Type representation in AIDL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AidlType {
    pub name: String,
    pub generic_args: Vec<AidlType>,
    pub array_dimensions: usize,
    pub is_nullable: bool,
}

impl AidlType {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            generic_args: Vec::new(),
            array_dimensions: 0,
            is_nullable: false,
        }
    }

    pub fn primitive(name: impl Into<String>) -> Self {
        Self::new(name)
    }

    pub fn is_primitive(&self) -> bool {
        matches!(
            self.name.as_str(),
            "void" | "boolean" | "byte" | "char" | "int" | "long" | "float" | "double"
        )
    }
}

/// Field in a parcelable or union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AidlField {
    pub annotations: Vec<Annotation>,
    pub ty: AidlType,
    pub name: String,
    pub default_value: Option<String>,
}

/// Constant inside interface or parcelable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AidlConstant {
    pub ty: AidlType,
    pub name: String,
    pub value: String,
}

/// Annotation attached to declarations, types, or fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    pub name: String,
    pub args: Vec<(Option<String>, String)>,
}
