module AST
  class StructType
    def typescript_decode(expr)
      String::Builder.build do |io|
        io << "{\n"
        fields.each do |field|
          io << ident "#{field.name}: #{field.type.typescript_decode("#{expr}.#{field.name}")},\n"
        end
        io << "}"
      end
    end

    def typescript_encode(expr)
      String::Builder.build do |io|
        io << "{\n"
        fields.each do |field|
          io << ident "#{field.name}: #{field.type.typescript_encode("#{expr}.#{field.name}")},\n"
        end
        io << "}"
      end
    end

    def typescript_native_type
      name
    end

    def typescript_definition
      String.build do |io|
        io << "export interface #{name} {\n"
        fields.each do |field|
          io << "    #{field.name}: #{field.type.typescript_native_type};\n"
        end
        io << "}"
      end
    end

    def typescript_expect(expr)
      String.build do |io|
        io << "expect(#{expr}).toBeTypeOf(\"object\");\n"
        fields.each do |field|
          io << field.type.typescript_expect("#{expr}.#{field.name}")
        end
      end
    end

    def typescript_check_encoded(expr, descr)
      String.build do |io|
        io << "if (#{expr} === null || #{expr} === undefined) {\n"
        io << "    const err = new Error(\"Invalid Type at '\" + #{descr} + \"', expected #{self.class.name}, got '\" + #{expr} + \"'\");\n"
        io << "    typeCheckerError(err, ctx);\n"
        io << "}\n"
        fields.each do |field|
          io << field.type.typescript_check_encoded("#{expr}.#{field.name}", "#{descr} + \".#{field.name}\"")
        end
      end
    end

    def typescript_check_decoded(expr, descr)
      String.build do |io|
        io << "if (#{expr} === null || #{expr} === undefined) {\n"
        io << "    const err = new Error(\"Invalid Type at '\" + #{descr} + \"', expected #{self.class.name}, got '\" + #{expr} + \"'\");\n"
        io << "    typeCheckerError(err, ctx);\n"
        io << "}\n"
        fields.each do |field|
          io << field.type.typescript_check_decoded("#{expr}.#{field.name}", "#{descr} + \".#{field.name}\"")
        end
      end
    end

    # KOTLIN
    def kt_decode(expr, desc)
      String::Builder.build do |io|
        io << "gson.fromJson(#{expr}.getJSONObject(\"result\")?.toString(), #{name}::class.java)"
      end
    end

    def kt_encode(expr, desc)
      String::Builder.build do |io|
        io << "gson.toJson(#{expr})"
      end
    end

    def kt_native_type
      name
    end

    def kt_definition
      String.build do |io|
        io << "data class #{name}(\n"
        index = 0
        fields.each do |field|
          io << "    var #{field.name}: #{field.type.kt_native_type}"

          suffix = ""
          if index < fields.size - 1
            suffix = ","
          end

          io << "#{suffix} \n"
          index += 1
        end
        io << "): Serializable {\n\n"
        io << "    companion object {\n"
        io << "        fun fromJson(jsonToParse : JSONObject): #{kt_native_type} {\n"
        io << "            return gson.fromJson(jsonToParse.toString(), #{name}::class.java)\n"
        io << "        }\n"
        io << "\n"
        io << "        fun fromJsonArray(jsonArrayToParse : JSONArray): ArrayList<#{kt_native_type}> {\n"
        io << "            return ArrayList(gson.fromJson(jsonArrayToParse.toString(), Array<#{name}>::class.java).toList())\n"
        io << "        }\n"
        io << "    }\n"

        toJsonExpr = "this@#{name}"
        io << "    fun toJson(): JSONObject {\n"
        io << "        return JSONObject(gson.toJson(this))"
        io << "    }"
        io << "}"
      end
    end

    def kt_return_type_name
      name[0].downcase + name[1..-1]
    end
    # KOTLIN

  end
end
