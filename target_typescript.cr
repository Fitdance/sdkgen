require "./target"

abstract class TypeScriptTarget < Target
  def native_type(t : AST::PrimitiveType)
    case t
    when AST::StringPrimitiveType;   "string"
    when AST::IntPrimitiveType;      "number"
    when AST::UIntPrimitiveType;     "number"
    when AST::FloatPrimitiveType;    "number"
    when AST::DatePrimitiveType;     "Date"
    when AST::DateTimePrimitiveType; "Date"
    when AST::BoolPrimitiveType;     "boolean"
    when AST::BytesPrimitiveType;    "Buffer"
    when AST::VoidPrimitiveType;     "null"
    else
      raise "BUG! Should handle primitive #{t.class}"
    end
  end

  def native_type(t : AST::OptionalType)
    native_type(t.base) + " | null"
  end

  def native_type(t : AST::CustomTypeReference)
    t.name
  end

  def generate_custom_type_interface(io, custom_type)
    io << "export interface #{custom_type.name} {\n"
    custom_type.fields.each do |field|
      io << "  #{field.name}: #{native_type field.type};\n"
    end
    io << "}\n"
  end

  def operation_name(op : AST::GetOperation)
    "get" + op.name[0].upcase + op.name[1..-1]
  end

  def operation_name(op : AST::FunctionOperation | AST::SubscribeOperation)
    op.name
  end

  def operation_ret(op : AST::GetOperation | AST::FunctionOperation)
    op.return_type.is_a?(AST::VoidPrimitiveType) ? "void" : native_type op.return_type
  end

  def operation_ret(op : AST::SubscribeOperation)
    "null"
  end

  def operation_args(op : AST::Operation)
    args = op.args.map {|arg| "#{arg.name}: #{native_type arg.type}" }
    if op.is_a? SubscribeOperation
      args << "callback: (result: #{native_type op.return_type}) => null"
    end

    "(#{args.join(", ")})"
  end

  def operation_type(op : AST::Operation)
    "#{operation_args(op)} => Promise<#{operation_ret(op)}>"
  end

  def type_from_json(t : AST::Type, src : String)
    case t
    when AST::StringPrimitiveType, AST::IntPrimitiveType, AST::UIntPrimitiveType, AST::FloatPrimitiveType, AST::BoolPrimitiveType
      "#{src}"
    when AST::DatePrimitiveType
      "moment.utc(#{src}, \"YYYY-MM-DD\").toDate()"
    when AST::DateTimePrimitiveType
      "moment.utc(#{src}, \"YYYY-MM-DDTHH:mm:ss.SSS\").toDate()"
    when AST::BytesPrimitiveType
      "Buffer.from(#{src}, \"base64\")"
    when AST::VoidPrimitiveType
      "undefined"
    when AST::OptionalType
      "#{src} === null || #{src} === undefined ? null : #{type_from_json(t.base, src)}"
    when AST::CustomTypeReference
      String::Builder.build do |io|
        io << "{\n"
        ct = @ast.custom_types.find {|x| x.name == t.name }.not_nil!
        ct.fields.each do |field|
          io << ident "#{field.name}: #{type_from_json(field.type, "#{src}.#{field.name}")},"
          io << "\n"
        end
        io << "}"
      end
    else
      raise "Unknown type"
    end
  end

  def type_to_json(t : AST::Type, src : String)
    case t
    when AST::StringPrimitiveType, AST::IntPrimitiveType, AST::UIntPrimitiveType, AST::FloatPrimitiveType, AST::BoolPrimitiveType
      "#{src}"
    when AST::DatePrimitiveType
      "moment(#{src}).format(\"YYYY-MM-DD\")"
    when AST::DateTimePrimitiveType
      "moment(#{src}).format(\"YYYY-MM-DDTHH:mm:ss.SSS\")"
    when AST::BytesPrimitiveType
      "#{src}.toString(\"base64\")"
    when AST::VoidPrimitiveType
      "null"
    when OptionalType
      "#{src} === null || #{src} === undefined ? null : #{type_to_json(t.base, src)}"
    when AST::CustomTypeReference
      String::Builder.build do |io|
        io << "{\n"
        ct = @ast.custom_types.find {|x| x.name == t.name }.not_nil!
        ct.fields.each do |field|
          io << ident "#{field.name}: #{type_to_json(field.type, "#{src}.#{field.name}")},"
          io << "\n"
        end
        io << "}"
      end
    else
      raise "Unknown type"
    end
  end
end