module AST
  class StringPrimitiveType
    def typescript_decode(expr)
      "#{expr}"
      # "#{expr}.normalize()"
    end

    def typescript_encode(expr)
      "#{expr}"
      # "#{expr}.normalize()"
    end

    def typescript_native_type
      "string"
    end

    def typescript_expect(expr)
      String.build do |io|
        io << "expect(#{expr}).toBeTypeOf(\"string\");\n"
      end
    end

    def typescript_check_encoded(expr, descr)
      String.build do |io|
        io << "if (#{expr} === null || #{expr} === undefined || typeof #{expr} !== \"string\") {\n"
        io << "    const err = new Error(\"Invalid Type at '\" + #{descr} + \"', expected #{self.class.name}, got '\" + #{expr} + \"'\");\n"
        io << "    typeCheckerError(err, ctx);\n"
        io << "}\n"
      end
    end

    def typescript_check_decoded(expr, descr)
      String.build do |io|
        io << "if (#{expr} === null || #{expr} === undefined || typeof #{expr} !== \"string\") {\n"
        io << "    const err = new Error(\"Invalid Type at '\" + #{descr} + \"', expected #{self.class.name}, got '\" + #{expr} + \"'\");\n"
        io << "    typeCheckerError(err, ctx);\n"
        io << "}\n"
      end
    end

# KOTLIN
    def kt_decode(expr, desc)
      "#{expr}.getString(\"#{desc}\")" 
    end 

    def kt_encode(expr)
      "#{expr}"
    end 

    def kt_native_type
      "String"
    end

    def kt_return_type_name
      "value"
    end
# KOTLIN

  end
end
