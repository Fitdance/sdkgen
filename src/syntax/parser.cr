require "./lexer"
require "../ast"

class Parser
  class ParserException < Exception
  end

  @lexers = [] of Lexer
  @token : Token | Nil

  def initialize(filename : String)
    @lexers << Lexer.new(File.read(filename), filename)
    read_next_token
  end

  def initialize(io : IO)
    @lexers << Lexer.new(io.gets_to_end)
    read_next_token
  end

  private def read_next_token
    while @lexers.size > 0
      @token = @lexers.last.next_token
      if @token
        return
      else
        @lexers.pop
      end
    end
  end

  private def current_filename
    @lexers.last.filename if @lexers.size > 0
  end

  def parse
    api = AST::ApiDescription.new
    while @token
      case multi_expect(ImportKeywordToken, TypeKeywordToken, GetKeywordToken, FunctionKeywordToken, GlobalOptionToken, ErrorKeywordToken)
      when ImportKeywordToken
        read_next_token
        token = expect StringLiteralToken
        source = File.expand_path(token.str + ".sdkgen", File.dirname(current_filename.not_nil!))
        @lexers << Lexer.new(File.read(source), source)
        read_next_token
      when TypeKeywordToken
        api.type_definitions << parse_type_definition
      when GetKeywordToken, FunctionKeywordToken
        api.operations << parse_operation
      when GlobalOptionToken
        parse_option(api.options)
      when ErrorKeywordToken
        read_next_token
        token = expect IdentifierToken
        read_next_token
        api.errors << token.name
      end
    end
    api
  end

  macro multi_expect(*token_types)
    token = @token
    unless token
      raise ParserException.new "Expected #{{{token_types.map { |t| t.stringify.gsub(/Token$/, "") }.join(" or ")}}}, but found end of file"
    end

    result = nil

    {% for token_type in token_types %}
      {% if token_type.stringify == "IdentifierToken" %}
        token = token.try_ident
      {% end %}
      if !result && token.is_a?({{token_type}})
        result = token
      end
    {% end %}

    unless result
      raise ParserException.new "Expected #{{{token_types.map { |t| t.stringify.gsub(/Token$/, "") }.join(" or ")}}} at #{token.location}, but found #{token}"
    end

    result
  end

  macro expect(token_type)
    token = @token
    unless token
      raise ParserException.new "Expected #{{{token_type.stringify.gsub(/Token$/, "")}}}, but found end of file"
    end
    {% if token_type.stringify == "IdentifierToken" %}
      token = token.try_ident
    {% end %}
    unless token.is_a?({{token_type}})
      raise ParserException.new "Expected #{{{token_type.stringify.gsub(/Token$/, "")}}} at #{token.location}, but found #{token}"
    end
    token
  end

  def parse_enum
    expect EnumKeywordToken
    read_next_token

    e = AST::EnumType.new

    expect CurlyOpenSymbolToken
    read_next_token

    while true
      case token = multi_expect(IdentifierToken, CurlyCloseSymbolToken)
      when IdentifierToken
        e.values << token.name
        read_next_token
      when CurlyCloseSymbolToken
        read_next_token
        return e
      end
    end
  end

  def parse_type_definition
    expect TypeKeywordToken
    read_next_token

    t = AST::TypeDefinition.new
    name_token = expect(IdentifierToken)
    unless name_token.name[0].uppercase?
      raise ParserException.new "The custom type name must start with an uppercase letter, but found '#{name_token.name}' at #{name_token.location}"
    end
    t.name = name_token.name
    read_next_token

    t.type = parse_type
    t
  end

  def parse_struct
    expect CurlyOpenSymbolToken
    read_next_token

    t = AST::StructType.new
    field_names = Set(String).new

    while true
      case token = multi_expect(IdentifierToken, CurlyCloseSymbolToken, SpreadSymbolToken)
      when IdentifierToken
        f = parse_field
        if field_names.includes? f.name
          raise ParserException.new "Cannot redeclare field '#{f.name}'"
        end
        field_names << f.name
        t.fields << f
      when SpreadSymbolToken
        read_next_token
        token = expect IdentifierToken
        unless token.name[0].uppercase?
          raise ParserException.new "Expected a type name but found '#{token.name}', at #{token.location}"
        end
        t.spreads << AST::TypeReference.new(token.name)
        read_next_token
      when CurlyCloseSymbolToken
        read_next_token
        return t
      end
    end
  end

  def parse_operation
    op = nil
    case token = multi_expect(GetKeywordToken, FunctionKeywordToken)
    when GetKeywordToken
      op = AST::GetOperation.new
    when FunctionKeywordToken
      op = AST::FunctionOperation.new
    else
      raise "never"
    end

    read_next_token
    op.name = expect(IdentifierToken).name
    ref_deprecated_location_token = @token.not_nil!
    read_next_token
    arg_names = Set(String).new

    if @token.is_a? ParensOpenSymbolToken
      read_next_token
      while true
        case token = multi_expect(IdentifierToken, ParensCloseSymbolToken, CommaSymbolToken)
        when IdentifierToken
          f = parse_field
          if arg_names.includes? f.name
            raise ParserException.new "Cannot redeclare argument '#{f.name}'"
          end
          arg_names << f.name
          op.args << f
        when ParensCloseSymbolToken
          read_next_token
          break
        when CommaSymbolToken
          read_next_token
          next
        end
      end
    else
      STDERR.puts "DEPRECATED: Should use '()' even for functions without arguments. See '#{op.name}' at #{ref_deprecated_location_token.location}.".colorize.light_yellow
    end

    if @token.is_a? ColonSymbolToken
      expect ColonSymbolToken
      read_next_token
      op.return_type = parse_type
    else
      op.return_type = AST::VoidPrimitiveType.new
    end

    op
  end

  def parse_option(options)
    var = expect GlobalOptionToken
    read_next_token
    expect EqualSymbolToken
    read_next_token

    case var.name
    when "url"
      token = expect StringLiteralToken
      read_next_token
      options.url = token.str
    when "useRethink"
      case token = multi_expect(TrueKeywordToken, FalseKeywordToken)
      when TrueKeywordToken
        options.useRethink = true
      when FalseKeywordToken
        options.useRethink = false
      end
      read_next_token
    when "retryRequest"
      case token = multi_expect(TrueKeywordToken, FalseKeywordToken)
      when TrueKeywordToken
        options.retryRequest = true
      when FalseKeywordToken
        options.retryRequest = false
      end
      read_next_token
    when "strict"
      case token = multi_expect(TrueKeywordToken, FalseKeywordToken)
      when TrueKeywordToken
        options.strict = true
      when FalseKeywordToken
        options.strict = false
      end
      read_next_token
    when "syntheticDefaultImports"
      case token = multi_expect(TrueKeywordToken, FalseKeywordToken)
      when TrueKeywordToken
        options.syntheticDefaultImports = true
      when FalseKeywordToken
        options.syntheticDefaultImports = false
      end
      read_next_token
    when "useDatadog"
      case token = multi_expect(TrueKeywordToken, FalseKeywordToken)
      when TrueKeywordToken
        options.useDatadog = true
      when FalseKeywordToken
        options.useDatadog = false
      end
      read_next_token
    else
      raise ParserException.new("Unknown option $#{var.name} at #{var.location}")
    end
  end

  def parse_field
    field = AST::Field.new
    field.name = expect(IdentifierToken).name
    read_next_token
    expect ColonSymbolToken
    read_next_token
    field.type = parse_type

    while @token.is_a?(ExclamationMarkSymbolToken)
      read_next_token
      case (token = expect(IdentifierToken)).name
      when "secret"
        field.secret = true
      else
        raise ParserException.new "Unknown field mark !#{token.name} at #{token.location}"
      end
      read_next_token
    end

    field
  end

  def parse_type
    case token = multi_expect(CurlyOpenSymbolToken, EnumKeywordToken, PrimitiveTypeToken, IdentifierToken)
    when CurlyOpenSymbolToken
      result = parse_struct
    when EnumKeywordToken
      result = parse_enum
    when IdentifierToken
      unless token.name[0].uppercase?
        raise ParserException.new "Expected a type but found '#{token.name}', at #{token.location}"
      end
      result = AST::TypeReference.new(token.name)
      read_next_token
    when PrimitiveTypeToken
      result = case token.name
               when "string"  ; AST::StringPrimitiveType.new
               when "int"     ; AST::IntPrimitiveType.new
               when "uint"    ; AST::UIntPrimitiveType.new
               when "date"    ; AST::DatePrimitiveType.new
               when "datetime"; AST::DateTimePrimitiveType.new
               when "float"   ; AST::FloatPrimitiveType.new
               when "bool"    ; AST::BoolPrimitiveType.new
               when "bytes"   ; AST::BytesPrimitiveType.new
               when "money"   ; AST::MoneyPrimitiveType.new
               when "cpf"     ; AST::CpfPrimitiveType.new
               when "cnpj"    ; AST::CnpjPrimitiveType.new
               when "email"   ; AST::EmailPrimitiveType.new
               when "phone"   ; AST::PhonePrimitiveType.new
               when "cep"     ; AST::CepPrimitiveType.new
               when "latlng"  ; AST::LatLngPrimitiveType.new
               when "url"     ; AST::UrlPrimitiveType.new
               when "uuid"    ; AST::UuidPrimitiveType.new
               when "hex"     ; AST::HexPrimitiveType.new
               when "base64"  ; AST::Base64PrimitiveType.new
               when "safehtml"; AST::SafeHtmlPrimitiveType.new
               when "xml"     ; AST::XmlPrimitiveType.new
               else
                 raise "BUG! Should handle primitive #{token.name}"
               end
      read_next_token
    else
      raise "never"
    end

    while @token.is_a? ArraySymbolToken || @token.is_a? OptionalSymbolToken
      case @token
      when ArraySymbolToken
        result = AST::ArrayType.new(result)
      when OptionalSymbolToken
        result = AST::OptionalType.new(result)
      end
      read_next_token
    end

    result
  end
end
