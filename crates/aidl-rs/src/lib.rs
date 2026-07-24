pub mod ast;
pub mod generator;
pub mod parser;

pub use ast::*;
pub use generator::*;
pub use parser::*;

pub fn parse_aidl(input: &str) -> Result<ast::AidlFile, parser::ParseError> {
    parser::Parser::parse_str(input)
}

pub fn generate_rust(file: &ast::AidlFile) -> String {
    generator::Generator::new().generate_file(file)
}
