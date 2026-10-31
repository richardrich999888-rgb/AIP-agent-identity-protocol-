//! Restricted arithmetic and condition language for capability procedures.
//!
//! A proposer (a local model or a person) writes expressions as text, e.g.
//! `ir_mohm * 2 ^ ((temp_c - 40) / 10)` or `temp_c < 10 or temp_c > 75`.
//! This module parses them into a bounded AST and evaluates them exactly.
//!
//! Deliberately excluded: function calls, assignment, loops, string
//! operations, indexing and any IO. The language is total over finite inputs
//! except for the stated errors (division by zero, non-finite results, an
//! exponent outside ±64), which make the whole capability refuse rather than
//! guess.
//!
//! Grammar (conditions are a disjunction of conjunctions of comparisons;
//! boolean parentheses are not supported, so there is no ambiguity with
//! arithmetic parentheses):
//!
//! ```text
//! cond   := conj ("or" conj)*
//! conj   := cmp ("and" cmp)*
//! cmp    := expr ("<" | "<=" | ">" | ">=" | "==" | "!=") expr
//! expr   := term (("+" | "-") term)*
//! term   := unary (("*" | "/") unary)*
//! unary  := "-" unary | power
//! power  := atom ("^" unary)?          // right-associative
//! atom   := number | ident | "(" expr ")"
//! ```

use std::collections::BTreeMap;

/// Limits that bound parse and evaluation work on hostile input.
pub const MAX_TOKENS: usize = 256;
pub const MAX_DEPTH: usize = 32;
pub const MAX_EXPONENT: f64 = 64.0;

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Num(f64),
    Var(String),
    Neg(Box<Expr>),
    Bin(Op, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Pow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

/// Disjunction of conjunctions of comparisons.
#[derive(Debug, Clone, PartialEq)]
pub struct Cond(pub Vec<Vec<(Expr, Cmp, Expr)>>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExprError {
    TooLong,
    TooDeep,
    Syntax(String),
    UnknownVariable(String),
    DivisionByZero,
    NonFinite,
    ExponentOutOfRange,
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64),
    Ident(String),
    Sym(&'static str),
}

fn lex(s: &str) -> Result<Vec<Tok>, ExprError> {
    let c: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        if out.len() > MAX_TOKENS {
            return Err(ExprError::TooLong);
        }
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch.is_ascii_digit()
            || (ch == '.' && c.get(i + 1).is_some_and(char::is_ascii_digit))
        {
            let st = i;
            while i < c.len() && (c[i].is_ascii_digit() || c[i] == '.') {
                i += 1;
            }
            let t: String = c[st..i].iter().collect();
            out.push(Tok::Num(
                t.parse()
                    .map_err(|_| ExprError::Syntax(format!("number {t}")))?,
            ));
        } else if ch.is_ascii_alphabetic() || ch == '_' {
            let st = i;
            while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_') {
                i += 1;
            }
            out.push(Tok::Ident(c[st..i].iter().collect()));
        } else {
            let two: String = c[i..(i + 2).min(c.len())].iter().collect();
            let sym = match two.as_str() {
                "<=" => Some("<="),
                ">=" => Some(">="),
                "==" => Some("=="),
                "!=" => Some("!="),
                _ => None,
            };
            if let Some(s2) = sym {
                out.push(Tok::Sym(s2));
                i += 2;
                continue;
            }
            let s1 = match ch {
                '+' => "+",
                '-' => "-",
                '*' => "*",
                '/' => "/",
                '^' => "^",
                '(' => "(",
                ')' => ")",
                '<' => "<",
                '>' => ">",
                _ => return Err(ExprError::Syntax(format!("character {ch:?}"))),
            };
            out.push(Tok::Sym(s1));
            i += 1;
        }
    }
    if out.len() > MAX_TOKENS {
        return Err(ExprError::TooLong);
    }
    Ok(out)
}

struct P {
    t: Vec<Tok>,
    i: usize,
    depth: usize,
}

impl P {
    fn peek_sym(&self, s: &str) -> bool {
        matches!(self.t.get(self.i), Some(Tok::Sym(x)) if *x == s)
    }
    fn peek_word(&self, w: &str) -> bool {
        matches!(self.t.get(self.i), Some(Tok::Ident(x)) if x == w)
    }
    fn enter(&mut self) -> Result<(), ExprError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            Err(ExprError::TooDeep)
        } else {
            Ok(())
        }
    }
    fn expr(&mut self) -> Result<Expr, ExprError> {
        self.enter()?;
        let mut l = self.term()?;
        loop {
            let op = if self.peek_sym("+") {
                Op::Add
            } else if self.peek_sym("-") {
                Op::Sub
            } else {
                break;
            };
            self.i += 1;
            l = Expr::Bin(op, Box::new(l), Box::new(self.term()?));
        }
        self.depth -= 1;
        Ok(l)
    }
    fn term(&mut self) -> Result<Expr, ExprError> {
        let mut l = self.unary()?;
        loop {
            let op = if self.peek_sym("*") {
                Op::Mul
            } else if self.peek_sym("/") {
                Op::Div
            } else {
                break;
            };
            self.i += 1;
            l = Expr::Bin(op, Box::new(l), Box::new(self.unary()?));
        }
        Ok(l)
    }
    fn unary(&mut self) -> Result<Expr, ExprError> {
        self.enter()?;
        let r = if self.peek_sym("-") {
            self.i += 1;
            Expr::Neg(Box::new(self.unary()?))
        } else {
            let a = self.atom()?;
            if self.peek_sym("^") {
                self.i += 1;
                Expr::Bin(Op::Pow, Box::new(a), Box::new(self.unary()?))
            } else {
                a
            }
        };
        self.depth -= 1;
        Ok(r)
    }
    fn atom(&mut self) -> Result<Expr, ExprError> {
        match self.t.get(self.i).cloned() {
            Some(Tok::Num(v)) => {
                self.i += 1;
                Ok(Expr::Num(v))
            }
            Some(Tok::Ident(n)) if !matches!(n.as_str(), "and" | "or") => {
                self.i += 1;
                Ok(Expr::Var(n))
            }
            Some(Tok::Sym("(")) => {
                self.i += 1;
                let e = self.expr()?;
                if !self.peek_sym(")") {
                    return Err(ExprError::Syntax("expected )".into()));
                }
                self.i += 1;
                Ok(e)
            }
            other => Err(ExprError::Syntax(format!("unexpected {other:?}"))),
        }
    }
    fn cmp(&mut self) -> Result<(Expr, Cmp, Expr), ExprError> {
        let l = self.expr()?;
        let op = match self.t.get(self.i) {
            Some(Tok::Sym("<")) => Cmp::Lt,
            Some(Tok::Sym("<=")) => Cmp::Le,
            Some(Tok::Sym(">")) => Cmp::Gt,
            Some(Tok::Sym(">=")) => Cmp::Ge,
            Some(Tok::Sym("==")) => Cmp::Eq,
            Some(Tok::Sym("!=")) => Cmp::Ne,
            other => {
                return Err(ExprError::Syntax(format!(
                    "expected comparison, got {other:?}"
                )))
            }
        };
        self.i += 1;
        Ok((l, op, self.expr()?))
    }
    fn done(&self) -> Result<(), ExprError> {
        if self.i == self.t.len() {
            Ok(())
        } else {
            Err(ExprError::Syntax(format!("trailing {:?}", self.t[self.i])))
        }
    }
}

/// Parse an arithmetic expression.
pub fn parse_expr(s: &str) -> Result<Expr, ExprError> {
    let mut p = P {
        t: lex(s)?,
        i: 0,
        depth: 0,
    };
    let e = p.expr()?;
    p.done()?;
    Ok(e)
}

/// Parse a condition.
pub fn parse_cond(s: &str) -> Result<Cond, ExprError> {
    let mut p = P {
        t: lex(s)?,
        i: 0,
        depth: 0,
    };
    let mut disj = vec![];
    loop {
        let mut conj = vec![p.cmp()?];
        while p.peek_word("and") {
            p.i += 1;
            conj.push(p.cmp()?);
        }
        disj.push(conj);
        if p.peek_word("or") {
            p.i += 1;
        } else {
            break;
        }
    }
    p.done()?;
    Ok(Cond(disj))
}

/// Variables referenced (sorted, unique).
pub fn vars_expr(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Num(_) => {}
        Expr::Var(v) => {
            if !out.contains(v) {
                out.push(v.clone());
            }
        }
        Expr::Neg(a) => vars_expr(a, out),
        Expr::Bin(_, a, b) => {
            vars_expr(a, out);
            vars_expr(b, out);
        }
    }
}

/// Variables referenced by a condition.
pub fn vars_cond(c: &Cond) -> Vec<String> {
    let mut v = vec![];
    for conj in &c.0 {
        for (a, _, b) in conj {
            vars_expr(a, &mut v);
            vars_expr(b, &mut v);
        }
    }
    v.sort();
    v
}

/// Evaluate with IEEE-754 double semantics (same as the Python reference,
/// so boundary comparisons agree bit-for-bit).
pub fn eval(e: &Expr, env: &BTreeMap<String, f64>) -> Result<f64, ExprError> {
    let v = match e {
        Expr::Num(v) => *v,
        Expr::Var(n) => *env
            .get(n)
            .ok_or_else(|| ExprError::UnknownVariable(n.clone()))?,
        Expr::Neg(a) => -eval(a, env)?,
        Expr::Bin(op, a, b) => {
            let (x, y) = (eval(a, env)?, eval(b, env)?);
            match op {
                Op::Add => x + y,
                Op::Sub => x - y,
                Op::Mul => x * y,
                Op::Div => {
                    if y == 0.0 {
                        return Err(ExprError::DivisionByZero);
                    }
                    x / y
                }
                Op::Pow => {
                    if y.abs() > MAX_EXPONENT {
                        return Err(ExprError::ExponentOutOfRange);
                    }
                    x.powf(y)
                }
            }
        }
    };
    if v.is_finite() {
        Ok(v)
    } else {
        Err(ExprError::NonFinite)
    }
}

/// Evaluate a condition.
pub fn eval_cond(c: &Cond, env: &BTreeMap<String, f64>) -> Result<bool, ExprError> {
    for conj in &c.0 {
        let mut all = true;
        for (a, op, b) in conj {
            let (x, y) = (eval(a, env)?, eval(b, env)?);
            let r = match op {
                Cmp::Lt => x < y,
                Cmp::Le => x <= y,
                Cmp::Gt => x > y,
                Cmp::Ge => x >= y,
                Cmp::Eq => x == y,
                Cmp::Ne => x != y,
            };
            if !r {
                all = false;
                break;
            }
        }
        if all {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(p: &[(&str, f64)]) -> BTreeMap<String, f64> {
        p.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn precedence_and_right_associative_power() {
        let e = env(&[]);
        assert_eq!(eval(&parse_expr("2 + 3 * 4").unwrap(), &e), Ok(14.0));
        assert_eq!(eval(&parse_expr("2 ^ 3 ^ 2").unwrap(), &e), Ok(512.0));
        assert_eq!(eval(&parse_expr("-2 ^ 2").unwrap(), &e), Ok(-4.0));
        assert_eq!(eval(&parse_expr("(1 + 1) * 3").unwrap(), &e), Ok(6.0));
    }

    #[test]
    fn temperature_correction_matches_reference_arithmetic() {
        let e = env(&[("ir_mohm", 30.0), ("temp_c", 50.0)]);
        let v = eval(
            &parse_expr("ir_mohm * 2 ^ ((temp_c - 40) / 10)").unwrap(),
            &e,
        )
        .unwrap();
        assert_eq!(v, 30.0 * 2f64.powf((50.0 - 40.0) / 10.0));
    }

    #[test]
    fn conditions_dnf() {
        let c = parse_cond("temp_c < 10 or temp_c > 75").unwrap();
        assert!(eval_cond(&c, &env(&[("temp_c", 80.0)])).unwrap());
        assert!(!eval_cond(&c, &env(&[("temp_c", 75.0)])).unwrap());
        let c = parse_cond("pi >= 1.5 and pi < 2").unwrap();
        assert!(eval_cond(&c, &env(&[("pi", 1.5)])).unwrap());
        assert_eq!(vars_cond(&c), vec!["pi".to_string()]);
    }

    #[test]
    fn failure_modes_fail_closed() {
        let e = env(&[("x", 0.0)]);
        assert_eq!(
            eval(&parse_expr("1 / x").unwrap(), &e),
            Err(ExprError::DivisionByZero)
        );
        assert_eq!(
            eval(&parse_expr("2 ^ 100").unwrap(), &e),
            Err(ExprError::ExponentOutOfRange)
        );
        assert_eq!(
            eval(&parse_expr("y + 1").unwrap(), &e),
            Err(ExprError::UnknownVariable("y".into()))
        );
        assert!(eval(
            &parse_expr("10 ^ 64 * 10 ^ 64 * 10 ^ 64 * 10 ^ 64 * 10 ^ 64").unwrap(),
            &e
        )
        .is_err());
    }

    #[test]
    fn rejects_code_and_hostile_input() {
        for bad in [
            "import os",
            "f(x)",
            "x = 1",
            "x;y",
            "\"s\"",
            "x[0]",
            "x < ",
            "(1",
            "1 2",
            "x < 1 and",
        ] {
            assert!(
                parse_expr(bad).is_err() || parse_cond(bad).is_err(),
                "{bad}"
            );
        }
        assert!(
            parse_cond("x < 1 or (x > 2)").is_err(),
            "boolean parentheses are not part of the language"
        );
        assert!(
            parse_cond("(x + 1) * 2 < 2 or x > 2").is_ok(),
            "arithmetic parentheses are"
        );
        assert_eq!(
            parse_expr(&"(".repeat(40).to_string()),
            Err(ExprError::TooDeep)
        );
        assert_eq!(parse_expr(&"1+".repeat(200)), Err(ExprError::TooLong));
    }
}
