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
    CharLit(String),
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
    Star,
    Slash,
    Percent,
    Amp,
    Pipe,
    Caret,
    Tilde,
    Bang,
    AndAnd,
    OrOr,
    EqEq,
    NotEq,
    LAngleAngle,
    RAngleAngle,
    LessEqual,
    GreaterEqual,
    Eof,
}

impl Token {
    pub fn description(&self) -> String {
        match self {
            Token::Ident(s) => format!("identifier '{s}'"),
            Token::StringLit(s) => format!("string \"{s}\""),
            Token::CharLit(s) => format!("character {s}"),
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
            Token::Star => "'*'".into(),
            Token::Slash => "'/'".into(),
            Token::Percent => "'%'".into(),
            Token::Amp => "'&'".into(),
            Token::Pipe => "'|'".into(),
            Token::Caret => "'^'".into(),
            Token::Tilde => "'~'".into(),
            Token::Bang => "'!'".into(),
            Token::AndAnd => "'&&'".into(),
            Token::OrOr => "'||'".into(),
            Token::EqEq => "'=='".into(),
            Token::NotEq => "'!='".into(),
            Token::LAngleAngle => "'<<'".into(),
            Token::RAngleAngle => "'>>'".into(),
            Token::LessEqual => "'<='".into(),
            Token::GreaterEqual => "'>='".into(),
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
                let token = if self.chars.peek().is_some_and(|&(_, c)| c == '=') {
                    self.chars.next();
                    Token::EqEq
                } else {
                    Token::Equals
                };
                tokens.push((token, idx));
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
                let token = if self.chars.peek().is_some_and(|&(_, c)| c == '<') {
                    self.chars.next();
                    Token::LAngleAngle
                } else if self.chars.peek().is_some_and(|&(_, c)| c == '=') {
                    self.chars.next();
                    Token::LessEqual
                } else {
                    Token::LAngle
                };
                tokens.push((token, idx));
                continue;
            }
            if ch == '>' {
                self.chars.next();
                let token = if self.chars.peek().is_some_and(|&(_, c)| c == '>') {
                    self.chars.next();
                    Token::RAngleAngle
                } else if self.chars.peek().is_some_and(|&(_, c)| c == '=') {
                    self.chars.next();
                    Token::GreaterEqual
                } else {
                    Token::RAngle
                };
                tokens.push((token, idx));
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
            let simple_operator = match ch {
                '*' => Some(Token::Star),
                '/' => Some(Token::Slash),
                '%' => Some(Token::Percent),
                '&' if self.chars.clone().nth(1).is_some_and(|(_, c)| c == '&') => {
                    self.chars.next();
                    Some(Token::AndAnd)
                }
                '&' => Some(Token::Amp),
                '|' if self.chars.clone().nth(1).is_some_and(|(_, c)| c == '|') => {
                    self.chars.next();
                    Some(Token::OrOr)
                }
                '|' => Some(Token::Pipe),
                '^' => Some(Token::Caret),
                '~' => Some(Token::Tilde),
                '!' if self.chars.clone().nth(1).is_some_and(|(_, c)| c == '=') => {
                    self.chars.next();
                    Some(Token::NotEq)
                }
                '!' => Some(Token::Bang),
                _ => None,
            };
            if let Some(token) = simple_operator {
                self.chars.next();
                tokens.push((token, idx));
                continue;
            }

            if ch == '"' {
                let s = self.read_string(idx)?;
                tokens.push((Token::StringLit(s), idx));
                continue;
            }

            if ch == '\'' {
                let value = self.read_char(idx)?;
                tokens.push((Token::CharLit(value), idx));
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

    fn read_char(&mut self, start_idx: usize) -> Result<String, ParseError> {
        self.chars.next();
        let value = match self.chars.next() {
            Some((_, '\\')) => match self.chars.next() {
                Some((_, escaped)) => match escaped {
                    'n' => '\n', 'r' => '\r', 't' => '\t', '\\' => '\\', '\'' => '\'', other => other,
                },
                None => return Err(ParseError::UnterminatedString(start_idx)),
            },
            Some((_, value)) => value,
            None => return Err(ParseError::UnterminatedString(start_idx)),
        };
        match self.chars.next() {
            Some((_, '\'')) => Ok(format!("'{value}'")),
            _ => Err(ParseError::UnterminatedString(start_idx)),
        }
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
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
                s.push(ch);
                self.chars.next();
            } else {
                break;
            }
        }
        let normalized = ["u8", "u32", "u64", "U8", "U32", "U64", "u", "U", "l", "L", "f"]
            .iter()
            .find_map(|suffix| s.strip_suffix(suffix))
            .unwrap_or(&s)
            .replace('_', "");
        if normalized.starts_with("0x") || normalized.starts_with("0X") {
            let val = i64::from_str_radix(&normalized[2..], 16)
                .map_err(|_| ParseError::InvalidNumber(s.clone(), start_idx))?;
            Ok(Token::IntLit(val))
        } else if normalized.contains('.') || normalized.contains('e') || normalized.contains('E') {
            let val = normalized.parse::<f64>()
                .map_err(|_| ParseError::InvalidNumber(s.clone(), start_idx))?;
            Ok(Token::FloatLit(val))
        } else {
            let val = normalized.parse::<i64>()
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
        self.parse_expression_bp(0)
    }

    fn parse_expression_bp(&mut self, min_precedence: u8) -> Result<String, ParseError> {
        let (tok, idx) = self.advance();
        let mut left = match tok {
            Token::StringLit(s) => format!("\"{s}\""),
            Token::CharLit(s) => s,
            Token::IntLit(n) => n.to_string(),
            Token::FloatLit(f) => f.to_string(),
            Token::Ident(s) => s,
            Token::Minus => format!("-{}", self.parse_expression_bp(10)?),
            Token::Plus => format!("+{}", self.parse_expression_bp(10)?),
            Token::Tilde => format!("~{}", self.parse_expression_bp(10)?),
            Token::Bang => format!("!{}", self.parse_expression_bp(10)?),
            Token::LParen => {
                let value = self.parse_expression_bp(0)?;
                self.expect_token(Token::RParen)?;
                if value.starts_with('(') && value.ends_with(')') {
                    value
                } else {
                    format!("({value})")
                }
            }
            other => return Err(ParseError::ExpectedToken {
                expected: "constant expression operand".into(),
                found: other.description(),
                location: idx,
            }),
        };

        while let Some((operator, precedence)) = self.binary_operator() {
            if precedence < min_precedence {
                break;
            }
            self.advance();
            let right = self.parse_expression_bp(precedence + 1)?;
            left = format!("({left}{operator}{right})");
        }
        Ok(left)
    }

    fn binary_operator(&self) -> Option<(&'static str, u8)> {
        let result = match self.peek().0 {
            Token::OrOr => ("||", 1),
            Token::AndAnd => ("&&", 2),
            Token::Pipe => ("|", 3),
            Token::Caret => ("^", 4),
            Token::Amp => ("&", 5),
            Token::EqEq => ("==", 6),
            Token::NotEq => ("!=", 6),
            Token::LAngle | Token::RAngle | Token::LessEqual | Token::GreaterEqual => {
                (match self.peek().0 {
                    Token::LAngle => "<",
                    Token::RAngle => ">",
                    Token::LessEqual => "<=",
                    _ => ">=",
                }, 7)
            }
            Token::LAngleAngle => ("<<", 8),
            Token::RAngleAngle => (">>", 8),
            Token::Plus => ("+", 9),
            Token::Minus => ("-", 9),
            Token::Star => ("*", 10),
            Token::Slash => ("/", 10),
            Token::Percent => ("%", 10),
            _ => return None,
        };
        Some(result)
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
            self.expect_generic_close()?;
        }

        let mut array_dimensions = 0;
        while let (Token::LBracket, _) = self.peek() {
            self.advance();
            self.expect_token(Token::RBracket)?;
            array_dimensions += 1;
        }

        let ty = AidlType {
            name,
            generic_args,
            array_dimensions,
            is_nullable,
        };
        self.validate_type_shape(&ty)?;
        Ok(ty)
    }

    fn validate_type_shape(&self, ty: &AidlType) -> Result<(), ParseError> {
        let builtin = matches!(
            ty.name.as_str(),
            "void" | "boolean" | "byte" | "char" | "int" | "long" | "float" | "double"
                | "String" | "IBinder"
        );
        if ty.name == "void" && (ty.array_dimensions != 0 || !ty.generic_args.is_empty()) {
            return Err(ParseError::Custom {
                message: "void cannot be an array or generic type".into(),
                location: 0,
            });
        }
        if builtin && !ty.generic_args.is_empty() {
            return Err(ParseError::Custom {
                message: format!("{} cannot have type arguments", ty.name),
                location: 0,
            });
        }
        let valid_arity = match ty.name.as_str() {
            "List" => ty.generic_args.len() == 1,
            // AOSP retains the Java-compatible raw Map shape as well as Map<K,V>.
            "Map" => ty.generic_args.is_empty() || ty.generic_args.len() == 2,
            _ => true,
        };
        if matches!(ty.name.as_str(), "List" | "Map") {
            if !valid_arity {
                let expected = if ty.name == "List" { "exactly 1" } else { "0 or 2" };
                return Err(ParseError::Custom {
                    message: format!("{} requires {} type arguments", ty.name, expected),
                    location: 0,
                });
            }
        } else if !ty.generic_args.is_empty() {
            return Err(ParseError::Custom {
                message: format!("{} is not a generic AIDL type", ty.name),
                location: 0,
            });
        }
        for arg in &ty.generic_args {
            self.validate_type_shape(arg)?;
        }
        Ok(())
    }

    fn expect_generic_close(&mut self) -> Result<usize, ParseError> {
        if let (Token::RAngleAngle, idx) = self.peek().clone() {
            self.advance();
            self.tokens.insert(self.pos, (Token::RAngle, idx + 1));
            Ok(idx)
        } else {
            self.expect_token(Token::RAngle)
        }
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

    #[test]
    fn test_interface_inheritance_is_preserved_in_rust_trait() {
        let aidl = r#"
            import com.example.IBase;
            interface IChild extends com.example.IBase {
                void run();
            }
        "#;
        let parsed = Parser::parse_str(aidl).expect("interface inheritance should parse");
        let code = Generator::new().generate_file(&parsed);
        assert!(code.contains("pub trait IChild: IBase + Send + Sync {"));
    }

    #[test]
    fn test_android_numeric_suffixes_and_char_literals() {
        let aidl = r#"
            interface Values {
                const int HEX = 0x10u32;
                const int DECIMAL = 1_000L;
                const char LETTER = 'a';
            }
        "#;
        let parsed = Parser::parse_str(aidl).expect("Android literal forms should parse");
        if let AidlDecl::Interface(iface) = &parsed.decls[0] {
            assert_eq!(iface.constants[0].value, "16");
            assert_eq!(iface.constants[1].value, "1000");
            assert_eq!(iface.constants[2].value, "'a'");
        } else {
            panic!("Expected interface decl");
        }
    }

    #[test]
    fn test_transaction_ids_use_binder_base() {
        let parsed = Parser::parse_str("interface IFoo { void first(); void second() = 7; }")
            .expect("interface should parse");
        let code = Generator::new().generate_file(&parsed);
        assert!(code.contains("TRANSACTION_first: u32 = FIRST_CALL_TRANSACTION + 0;"));
        assert!(code.contains("TRANSACTION_second: u32 = FIRST_CALL_TRANSACTION + 7;"));
        assert!(code.contains("FIRST_CALL_TRANSACTION: u32 = 1;"));
    }

    #[test]
    fn test_constant_expressions_accept_aidl_operators_and_parentheses() {
        let parsed = Parser::parse_str(
            "interface Values { const int MASK = (1 << 4) | 3; const boolean ENABLED = true && !false; }",
        )
        .expect("AIDL constant expressions should parse");
        if let AidlDecl::Interface(iface) = &parsed.decls[0] {
            assert_eq!(iface.constants[0].value, "((1<<4)|3)");
            assert_eq!(iface.constants[1].value, "(true&&!false)");
        } else {
            panic!("Expected interface decl");
        }
    }

    #[test]
    fn test_invalid_generic_type_shape_is_rejected() {
        let error = Parser::parse_str("interface Bad { void run(Map<String> value); }")
            .expect_err("Map must have exactly two type arguments");
        assert!(error.to_string().contains("Map requires 0 or 2 type arguments"));
    }
}
