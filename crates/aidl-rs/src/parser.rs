use crate::ast::*;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("Unexpected end of file")]
    UnexpectedEof,
    #[error("Unexpected character '{0}' at index {1}")]
    UnexpectedChar(char, usize),
    #[error("Unterminated comment starting at index {0}")]
    UnterminatedComment(usize),
    #[error("Unterminated string starting at index {0}")]
    UnterminatedString(usize),
    #[error("Invalid number '{0}' at index {1}")]
    InvalidNumber(String, usize),
    #[error("Expected token '{expected}', found '{found}' at index {location}")]
    ExpectedToken {
        expected: String,
        found: String,
        location: usize,
    },
    #[error("Parse error at index {location}: {message}")]
    Custom { message: String, location: usize },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Ident(String),
    StringLit(String),
    IntLit(i64),
    FloatLit(f64),
    At,
    Semi,
    Comma,
    Dot,
    Colon,
    Equals,
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    LAngle,
    RAngle,
    Plus,
    Minus,
    Eof,
}

impl Token {
    pub fn description(&self) -> String {
        match self {
            Token::Ident(s) => format!("identifier '{s}'"),
            Token::StringLit(s) => format!("string \"{s}\""),
            Token::IntLit(n) => format!("integer '{n}'"),
            Token::FloatLit(f) => format!("float '{f}'"),
            Token::At => "'@'".into(),
            Token::Semi => "';'".into(),
            Token::Comma => "','".into(),
            Token::Dot => "'.'".into(),
            Token::Colon => "':'".into(),
            Token::Equals => "'='".into(),
            Token::LBrace => "'{'".into(),
            Token::RBrace => "'}'".into(),
            Token::LParen => "'('".into(),
            Token::RParen => "')'".into(),
            Token::LBracket => "'['".into(),
            Token::RBracket => "']'".into(),
            Token::LAngle => "'<'".into(),
            Token::RAngle => "'>'".into(),
            Token::Plus => "'+'".into(),
            Token::Minus => "'-'".into(),
            Token::Eof => "EOF".into(),
        }
    }
}

pub struct Lexer<'a> {
    input: &'a str,
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            chars: input.char_indices().peekable(),
        }
    }

    pub fn tokenize(&mut self) -> Result<Vec<(Token, usize)>, ParseError> {
        let mut tokens = Vec::new();
        while let Some(&(idx, ch)) = self.chars.peek() {
            if ch.is_whitespace() {
                self.chars.next();
                continue;
            }

            if ch == '/' {
                self.chars.next();
                if let Some(&(_, next_ch)) = self.chars.peek() {
                    if next_ch == '/' {
                        self.chars.next();
                        while let Some((_, c)) = self.chars.next() {
                            if c == '\n' {
                                break;
                            }
                        }
                        continue;
                    } else if next_ch == '*' {
                        self.chars.next();
                        let mut closed = false;
                        while let Some((_, c)) = self.chars.next() {
                            if c == '*' {
                                if let Some(&(_, '/')) = self.chars.peek() {
                                    self.chars.next();
                                    closed = true;
                                    break;
                                }
                            }
                        }
                        if !closed {
                            return Err(ParseError::UnterminatedComment(idx));
                        }
                        continue;
                    } else {
                        return Err(ParseError::UnexpectedChar('/', idx));
                    }
                }
            }

            if ch == '@' {
                self.chars.next();
                tokens.push((Token::At, idx));
                continue;
            }
            if ch == ';' {
                self.chars.next();
                tokens.push((Token::Semi, idx));
                continue;
            }
            if ch == ',' {
                self.chars.next();
                tokens.push((Token::Comma, idx));
                continue;
            }
            if ch == '.' {
                self.chars.next();
                tokens.push((Token::Dot, idx));
                continue;
            }
            if ch == ':' {
                self.chars.next();
                tokens.push((Token::Colon, idx));
                continue;
            }
            if ch == '=' {
                self.chars.next();
                tokens.push((Token::Equals, idx));
                continue;
            }
            if ch == '{' {
                self.chars.next();
                tokens.push((Token::LBrace, idx));
                continue;
            }
            if ch == '}' {
                self.chars.next();
                tokens.push((Token::RBrace, idx));
                continue;
            }
            if ch == '(' {
                self.chars.next();
                tokens.push((Token::LParen, idx));
                continue;
            }
            if ch == ')' {
                self.chars.next();
                tokens.push((Token::RParen, idx));
                continue;
            }
            if ch == '[' {
                self.chars.next();
                tokens.push((Token::LBracket, idx));
                continue;
            }
            if ch == ']' {
                self.chars.next();
                tokens.push((Token::RBracket, idx));
                continue;
            }
            if ch == '<' {
                self.chars.next();
                tokens.push((Token::LAngle, idx));
                continue;
            }
            if ch == '>' {
                self.chars.next();
                tokens.push((Token::RAngle, idx));
                continue;
            }
            if ch == '+' {
                self.chars.next();
                tokens.push((Token::Plus, idx));
                continue;
            }
            if ch == '-' {
                self.chars.next();
                tokens.push((Token::Minus, idx));
                continue;
            }

            if ch == '"' {
                let s = self.read_string(idx)?;
                tokens.push((Token::StringLit(s), idx));
                continue;
            }

            if ch.is_ascii_digit() {
                let tok = self.read_number(idx)?;
                tokens.push((tok, idx));
                continue;
            }

            if ch.is_ascii_alphabetic() || ch == '_' {
                let ident = self.read_ident();
                tokens.push((Token::Ident(ident), idx));
                continue;
            }

            return Err(ParseError::UnexpectedChar(ch, idx));
        }

        tokens.push((Token::Eof, self.input.len()));
        Ok(tokens)
    }

    fn read_string(&mut self, start_idx: usize) -> Result<String, ParseError> {
        self.chars.next();
        let mut s = String::new();
        while let Some((_, ch)) = self.chars.next() {
            if ch == '"' {
                return Ok(s);
            }
            if ch == '\\' {
                if let Some((_, escaped)) = self.chars.next() {
                    match escaped {
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        '\\' => s.push('\\'),
                        '"' => s.push('"'),
                        '0' => s.push('\0'),
                        other => s.push(other),
                    }
                } else {
                    return Err(ParseError::UnterminatedString(start_idx));
                }
            } else {
                s.push(ch);
            }
        }
        Err(ParseError::UnterminatedString(start_idx))
    }

    fn read_ident(&mut self) -> String {
        let mut s = String::new();
        while let Some(&(_, ch)) = self.chars.peek() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                s.push(ch);
                self.chars.next();
            } else {
                break;
            }
        }
        s
    }

    fn read_number(&mut self, start_idx: usize) -> Result<Token, ParseError> {
        let mut s = String::new();
        while let Some(&(_, ch)) = self.chars.peek() {
            if ch.is_ascii_hexdigit() || ch == 'x' || ch == 'X' || ch == 'b' || ch == 'B' || ch == '.' {
                s.push(ch);
                self.chars.next();
            } else {
                break;
            }
        }
        if s.starts_with("0x") || s.starts_with("0X") {
            let val = i64::from_str_radix(&s[2..], 16)
                .map_err(|_| ParseError::InvalidNumber(s.clone(), start_idx))?;
            Ok(Token::IntLit(val))
        } else if s.starts_with("0b") || s.starts_with("0B") {
            let val = i64::from_str_radix(&s[2..], 2)
                .map_err(|_| ParseError::InvalidNumber(s.clone(), start_idx))?;
            Ok(Token::IntLit(val))
        } else if s.contains('.') {
            let val = s.parse::<f64>()
                .map_err(|_| ParseError::InvalidNumber(s.clone(), start_idx))?;
            Ok(Token::FloatLit(val))
        } else {
            let val = s.parse::<i64>()
                .map_err(|_| ParseError::InvalidNumber(s.clone(), start_idx))?;
            Ok(Token::IntLit(val))
        }
    }
}

pub struct Parser {
    tokens: Vec<(Token, usize)>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<(Token, usize)>) -> Self {
        Self { tokens, pos: 0 }
    }

    pub fn parse_str(input: &str) -> Result<AidlFile, ParseError> {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize()?;
        let mut parser = Parser::new(tokens);
        parser.parse_file()
    }

    fn peek(&self) -> &(Token, usize) {
        if self.pos < self.tokens.len() {
            &self.tokens[self.pos]
        } else {
            &self.tokens[self.tokens.len() - 1]
        }
    }

    fn advance(&mut self) -> (Token, usize) {
        let tok = self.peek().clone();
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    fn match_ident(&mut self, expected: &str) -> bool {
        if let (Token::Ident(s), _) = self.peek() {
            if s == expected {
                self.advance();
                return true;
            }
        }
        false
    }

    fn expect_ident(&mut self) -> Result<(String, usize), ParseError> {
        let (tok, idx) = self.advance();
        if let Token::Ident(s) = tok {
            Ok((s, idx))
        } else {
            Err(ParseError::ExpectedToken {
                expected: "identifier".into(),
                found: tok.description(),
                location: idx,
            })
        }
    }

    fn expect_token(&mut self, expected_tok: Token) -> Result<usize, ParseError> {
        let (tok, idx) = self.advance();
        if tok == expected_tok {
            Ok(idx)
        } else {
            Err(ParseError::ExpectedToken {
                expected: expected_tok.description(),
                found: tok.description(),
                location: idx,
            })
        }
    }

    fn parse_qualified_ident(&mut self) -> Result<String, ParseError> {
        let (mut name, _) = self.expect_ident()?;
        while let (Token::Dot, _) = self.peek() {
            self.advance();
            let (part, _) = self.expect_ident()?;
            name.push('.');
            name.push_str(&part);
        }
        Ok(name)
    }

    pub fn parse_file(&mut self) -> Result<AidlFile, ParseError> {
        let mut file = AidlFile::default();

        while self.peek().0 != Token::Eof {
            if let Token::Ident(id) = &self.peek().0 {
                if id == "package" {
                    self.advance();
                    let pkg = self.parse_qualified_ident()?;
                    self.expect_token(Token::Semi)?;
                    file.package = Some(pkg);
                    continue;
                } else if id == "import" {
                    self.advance();
                    let imp = self.parse_qualified_ident()?;
                    self.expect_token(Token::Semi)?;
                    file.imports.push(imp);
                    continue;
                }
            }

            let decl = self.parse_decl()?;
            file.decls.push(decl);
        }

        Ok(file)
    }

    fn parse_annotations(&mut self) -> Result<Vec<Annotation>, ParseError> {
        let mut annos = Vec::new();
        while let (Token::At, _) = self.peek() {
            self.advance();
            let (name, _) = self.expect_ident()?;
            let mut args = Vec::new();
            if let (Token::LParen, _) = self.peek() {
                self.advance();
                while self.peek().0 != Token::RParen {
                    let key = if let (Token::Ident(k), _) = self.peek() {
                        let k_str = k.clone();
                        if self.pos + 1 < self.tokens.len()
                            && self.tokens[self.pos + 1].0 == Token::Equals
                        {
                            self.advance(); // consume k
                            self.advance(); // consume =
                            Some(k_str)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let val = self.parse_expression_as_string()?;
                    args.push((key, val));

                    if let (Token::Comma, _) = self.peek() {
                        self.advance();
                    } else {
                        break;
                    }
                }
                self.expect_token(Token::RParen)?;
            }
            annos.push(Annotation { name, args });
        }
        Ok(annos)
    }

    fn parse_expression_as_string(&mut self) -> Result<String, ParseError> {
        let (tok, idx) = self.advance();
        match tok {
            Token::StringLit(s) => Ok(format!("\"{s}\"")),
            Token::IntLit(n) => Ok(n.to_string()),
            Token::FloatLit(f) => Ok(f.to_string()),
            Token::Ident(s) => Ok(s),
            Token::Minus => {
                let sub = self.parse_expression_as_string()?;
                Ok(format!("-{sub}"))
            }
            Token::Plus => {
                let sub = self.parse_expression_as_string()?;
                Ok(format!("+{sub}"))
            }
            other => Err(ParseError::ExpectedToken {
                expected: "literal or identifier".into(),
                found: other.description(),
                location: idx,
            }),
        }
    }

    fn parse_decl(&mut self) -> Result<AidlDecl, ParseError> {
        let annotations = self.parse_annotations()?;

        let mut is_oneway = false;
        if self.match_ident("oneway") {
            is_oneway = true;
        }

        let (kind, idx) = self.expect_ident()?;
        match kind.as_str() {
            "interface" => {
                let (name, _) = self.expect_ident()?;
                let mut extends = None;
                if self.match_ident("extends") {
                    extends = Some(self.parse_qualified_ident()?);
                }
                self.expect_token(Token::LBrace)?;
                let mut methods = Vec::new();
                let mut constants = Vec::new();

                while self.peek().0 != Token::RBrace {
                    let member_annos = self.parse_annotations()?;
                    if self.match_ident("const") {
                        let ty = self.parse_type()?;
                        let (cname, _) = self.expect_ident()?;
                        self.expect_token(Token::Equals)?;
                        let val = self.parse_expression_as_string()?;
                        self.expect_token(Token::Semi)?;
                        constants.push(AidlConstant {
                            ty,
                            name: cname,
                            value: val,
                        });
                    } else {
                        let m_oneway = self.match_ident("oneway");
                        let mut return_type = self.parse_type()?;
                        if member_annos.iter().any(|a| a.name == "nullable") {
                            return_type.is_nullable = true;
                        }
                        let (mname, _) = self.expect_ident()?;
                        self.expect_token(Token::LParen)?;
                        let mut args = Vec::new();

                        while self.peek().0 != Token::RParen {
                            let arg_annos = self.parse_annotations()?;
                            let mut dir = None;
                            if let (Token::Ident(d), _) = self.peek() {
                                match d.as_str() {
                                    "in" => {
                                        self.advance();
                                        dir = Some(Direction::In);
                                    }
                                    "out" => {
                                        self.advance();
                                        dir = Some(Direction::Out);
                                    }
                                    "inout" => {
                                        self.advance();
                                        dir = Some(Direction::InOut);
                                    }
                                    _ => {}
                                }
                            }

                            let arg_ty = self.parse_type()?;
                            let (arg_name, _) = self.expect_ident()?;
                            args.push(AidlArg {
                                annotations: arg_annos,
                                direction: dir,
                                ty: arg_ty,
                                name: arg_name,
                            });

                            if let (Token::Comma, _) = self.peek() {
                                self.advance();
                            } else {
                                break;
                            }
                        }

                        self.expect_token(Token::RParen)?;

                        let mut id = None;
                        if let (Token::Equals, _) = self.peek() {
                            self.advance();
                            let (id_tok, id_idx) = self.advance();
                            if let Token::IntLit(n) = id_tok {
                                id = Some(n as u32);
                            } else {
                                return Err(ParseError::ExpectedToken {
                                    expected: "integer transaction ID".into(),
                                    found: id_tok.description(),
                                    location: id_idx,
                                });
                            }
                        }

                        self.expect_token(Token::Semi)?;

                        methods.push(AidlMethod {
                            annotations: member_annos,
                            is_oneway: is_oneway || m_oneway,
                            return_type,
                            name: mname,
                            args,
                            id,
                        });
                    }
                }

                self.expect_token(Token::RBrace)?;

                Ok(AidlDecl::Interface(AidlInterface {
                    annotations,
                    is_oneway,
                    name,
                    extends,
                    methods,
                    constants,
                }))
            }

            "parcelable" => {
                let (name, _) = self.expect_ident()?;
                let mut cpp_header = None;

                if self.match_ident("cpp_header") {
                    let (tok, idx) = self.advance();
                    if let Token::StringLit(h) = tok {
                        cpp_header = Some(h);
                    } else {
                        return Err(ParseError::ExpectedToken {
                            expected: "string header path".into(),
                            found: tok.description(),
                            location: idx,
                        });
                    }
                }

                if let (Token::Semi, _) = self.peek() {
                    self.advance();
                    return Ok(AidlDecl::Parcelable(AidlParcelable {
                        annotations,
                        name,
                        cpp_header,
                        fields: Vec::new(),
                    }));
                }

                self.expect_token(Token::LBrace)?;
                let mut fields = Vec::new();

                while self.peek().0 != Token::RBrace {
                    let field_annos = self.parse_annotations()?;
                    let mut fty = self.parse_type()?;
                    if field_annos.iter().any(|a| a.name == "nullable") {
                        fty.is_nullable = true;
                    }
                    let (fname, _) = self.expect_ident()?;

                    let mut default_value = None;
                    if let (Token::Equals, _) = self.peek() {
                        self.advance();
                        default_value = Some(self.parse_expression_as_string()?);
                    }

                    self.expect_token(Token::Semi)?;

                    fields.push(AidlField {
                        annotations: field_annos,
                        ty: fty,
                        name: fname,
                        default_value,
                    });
                }

                self.expect_token(Token::RBrace)?;

                Ok(AidlDecl::Parcelable(AidlParcelable {
                    annotations,
                    name,
                    cpp_header,
                    fields,
                }))
            }

            "enum" => {
                let (name, _) = self.expect_ident()?;
                self.expect_token(Token::LBrace)?;
                let mut variants = Vec::new();

                while self.peek().0 != Token::RBrace {
                    let (vname, _) = self.expect_ident()?;
                    let mut value = None;
                    if let (Token::Equals, _) = self.peek() {
                        self.advance();
                        value = Some(self.parse_expression_as_string()?);
                    }

                    variants.push(EnumVariant { name: vname, value });

                    if let (Token::Comma, _) = self.peek() {
                        self.advance();
                    } else {
                        break;
                    }
                }

                self.expect_token(Token::RBrace)?;

                Ok(AidlDecl::Enum(AidlEnum {
                    annotations,
                    name,
                    backing_type: None,
                    variants,
                }))
            }

            "union" => {
                let (name, _) = self.expect_ident()?;
                self.expect_token(Token::LBrace)?;
                let mut fields = Vec::new();

                while self.peek().0 != Token::RBrace {
                    let fannos = self.parse_annotations()?;
                    let fty = self.parse_type()?;
                    let (fname, _) = self.expect_ident()?;
                    self.expect_token(Token::Semi)?;

                    fields.push(AidlField {
                        annotations: fannos,
                        ty: fty,
                        name: fname,
                        default_value: None,
                    });
                }

                self.expect_token(Token::RBrace)?;

                Ok(AidlDecl::Union(AidlUnion {
                    annotations,
                    name,
                    fields,
                }))
            }

            other => Err(ParseError::Custom {
                message: format!("Unknown declaration type '{other}'"),
                location: idx,
            }),
        }
    }

    fn parse_type(&mut self) -> Result<AidlType, ParseError> {
        let mut is_nullable = false;
        let annos = self.parse_annotations()?;
        if annos.iter().any(|a| a.name == "nullable") {
            is_nullable = true;
        }

        let name = self.parse_qualified_ident()?;
        let mut generic_args = Vec::new();

        if let (Token::LAngle, _) = self.peek() {
            self.advance();
            while self.peek().0 != Token::RAngle {
                let gty = self.parse_type()?;
                generic_args.push(gty);
                if let (Token::Comma, _) = self.peek() {
                    self.advance();
                } else {
                    break;
                }
            }
            self.expect_token(Token::RAngle)?;
        }

        let mut array_dimensions = 0;
        while let (Token::LBracket, _) = self.peek() {
            self.advance();
            self.expect_token(Token::RBracket)?;
            array_dimensions += 1;
        }

        Ok(AidlType {
            name,
            generic_args,
            array_dimensions,
            is_nullable,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::Generator;

    #[test]
    fn test_parse_package_and_imports() {
        let aidl = r#"
            package com.example.service;

            import com.example.model.Foo;
            import android.os.IBinder;

            interface ITestService {
                void ping();
            }
        "#;

        let parsed = Parser::parse_str(aidl).expect("Failed to parse AIDL");
        assert_eq!(parsed.package, Some("com.example.service".to_string()));
        assert_eq!(
            parsed.imports,
            vec![
                "com.example.model.Foo".to_string(),
                "android.os.IBinder".to_string()
            ]
        );
        assert_eq!(parsed.decls.len(), 1);
        if let AidlDecl::Interface(iface) = &parsed.decls[0] {
            assert_eq!(iface.name, "ITestService");
            assert_eq!(iface.methods.len(), 1);
            assert_eq!(iface.methods[0].name, "ping");
        } else {
            panic!("Expected interface decl");
        }
    }

    #[test]
    fn test_parse_interface_methods_directions_and_ids() {
        let aidl = r#"
            package com.example.binder;

            @utf8InCpp
            interface IMyService {
                const int CONST_VAL = 100;

                void sendData(in int id, in String text, in byte[] payload) = 1;
                @nullable String receiveData(out byte[] buffer) = 2;
                oneway void notifyEvent(inout List<String> items);
            }
        "#;

        let parsed = Parser::parse_str(aidl).expect("Failed to parse interface AIDL");
        if let AidlDecl::Interface(iface) = &parsed.decls[0] {
            assert_eq!(iface.name, "IMyService");
            assert_eq!(iface.constants.len(), 1);
            assert_eq!(iface.constants[0].name, "CONST_VAL");
            assert_eq!(iface.constants[0].value, "100");

            assert_eq!(iface.methods.len(), 3);

            let m1 = &iface.methods[0];
            assert_eq!(m1.name, "sendData");
            assert_eq!(m1.id, Some(1));
            assert_eq!(m1.args.len(), 3);
            assert_eq!(m1.args[0].direction, Some(Direction::In));
            assert_eq!(m1.args[0].ty.name, "int");
            assert_eq!(m1.args[1].direction, Some(Direction::In));
            assert_eq!(m1.args[1].ty.name, "String");
            assert_eq!(m1.args[2].direction, Some(Direction::In));
            assert_eq!(m1.args[2].ty.name, "byte");
            assert_eq!(m1.args[2].ty.array_dimensions, 1);

            let m2 = &iface.methods[1];
            assert_eq!(m2.name, "receiveData");
            assert_eq!(m2.id, Some(2));
            assert!(m2.return_type.is_nullable);

            let m3 = &iface.methods[2];
            assert_eq!(m3.name, "notifyEvent");
            assert!(m3.is_oneway);
            assert_eq!(m3.args[0].direction, Some(Direction::InOut));
            assert_eq!(m3.args[0].ty.name, "List");
            assert_eq!(m3.args[0].ty.generic_args[0].name, "String");
        } else {
            panic!("Expected interface decl");
        }
    }

    #[test]
    fn test_parse_parcelable_and_codegen() {
        let aidl = r#"
            package com.example.data;

            parcelable Foo {
                int id;
                String tag = "default";
                byte[] data;
            }
        "#;

        let parsed = Parser::parse_str(aidl).expect("Failed to parse parcelable AIDL");
        if let AidlDecl::Parcelable(p) = &parsed.decls[0] {
            assert_eq!(p.name, "Foo");
            assert_eq!(p.fields.len(), 3);
            assert_eq!(p.fields[0].name, "id");
            assert_eq!(p.fields[1].name, "tag");
            assert_eq!(p.fields[1].default_value, Some("\"default\"".to_string()));
            assert_eq!(p.fields[2].name, "data");
            assert_eq!(p.fields[2].ty.array_dimensions, 1);
        } else {
            panic!("Expected parcelable decl");
        }

        let generator = Generator::new();
        let code = generator.generate_file(&parsed);
        assert!(code.contains("pub struct Foo"));
        assert!(code.contains("pub id: i32"));
        assert!(code.contains("pub tag: String"));
        assert!(code.contains("pub data: Vec<i8>"));
    }

    #[test]
    fn test_parse_enum_and_union() {
        let aidl = r#"
            package com.example.types;

            enum Status {
                OK = 0,
                ERROR = 1,
            }

            union Payload {
                int number;
                String text;
            }
        "#;

        let parsed = Parser::parse_str(aidl).expect("Failed to parse enum/union AIDL");
        assert_eq!(parsed.decls.len(), 2);

        if let AidlDecl::Enum(e) = &parsed.decls[0] {
            assert_eq!(e.name, "Status");
            assert_eq!(e.variants.len(), 2);
            assert_eq!(e.variants[0].name, "OK");
            assert_eq!(e.variants[1].name, "ERROR");
        } else {
            panic!("Expected enum decl");
        }

        if let AidlDecl::Union(u) = &parsed.decls[1] {
            assert_eq!(u.name, "Payload");
            assert_eq!(u.fields.len(), 2);
            assert_eq!(u.fields[0].name, "number");
            assert_eq!(u.fields[1].name, "text");
        } else {
            panic!("Expected union decl");
        }

        let generator = Generator::new();
        let code = generator.generate_file(&parsed);
        assert!(code.contains("pub enum Status"));
        assert!(code.contains("pub enum Payload"));
        assert!(code.contains("Number(i32)"));
        assert!(code.contains("Text(String)"));
    }
}
