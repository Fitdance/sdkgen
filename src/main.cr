require "./syntax/parser"
require "./semantic/ast_semantic"
require "./target/java_android"
require "./target/kt_android"
require "./target/swift_ios"
require "./target/typescript_nodeserver"
require "./target/typescript_nodeclient"
require "./target/typescript_servertest"
require "./target/typescript_web"
require "option_parser"
require "file_utils"
require "colorize"

is_server = false
destination = ""
target_name = ""
use_dd = false
no_use_dd = false
sources = [] of String

OptionParser.parse do |parser|
  parser.banner = "Usage: salute [arguments]"
  parser.on("-o NAME", "--output=NAME", "Specifies the output file") { |name| destination = name }
  parser.on("-t TARGET", "--target=TARGET", "Specifies the target platform") { |target| target_name = target }
  parser.on("--use-datadog", "Enable Datadog support") { use_dd = true }
  parser.on("--no-use-datadog", "Disable Datadog support") { no_use_dd = true }
  parser.on("-h", "--help", "Show this help") { puts parser }
  parser.unknown_args { |args| sources = args }
end

if sources.size == 0
  STDERR.puts "You must specify one source file"
  exit 1
elsif sources.size > 1
  STDERR.puts "You must specify only one source file"
  exit 1
end

if use_dd && no_use_dd
  STDERR.puts "Cannot specify --use-datadog and --no-use-datadog at the same time"
  exit 1
end

source = sources[0]

begin
  parser = Parser.new(source)
  ast = parser.parse
  ast.semantic
  if use_dd
    ast.options.useDatadog = true
  end

  if no_use_dd
    ast.options.useDatadog = false
  end

  if destination == ""
    STDERR.puts "You must specify an output file"
    exit 1
  end

  if target_name == ""
    STDERR.puts "You must specify a target"
    exit 1
  end

  FileUtils.mkdir_p(File.dirname(destination))
  Target.process(ast, destination, target_name)
rescue ex : Lexer::LexerException | Parser::ParserException | Semantic::SemanticException
  STDERR.puts (ex.message || "Invalid source").colorize.light_red
  exit 1
rescue ex : Exception
  raise ex
end
