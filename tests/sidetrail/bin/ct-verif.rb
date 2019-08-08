#!/usr/bin/env ruby

require 'optparse'
require "open3"
require 'date'
require 'timeout'

def run_command_with_heartbeat (beat_time, cmd)
  start = Time.now
  line = nil
  puts "+ #{cmd}"
  Open3.popen3(cmd) do |stdin, stdout, stderr, thread|    
    loop do
      begin
        Timeout::timeout(beat_time) {line = stdout.gets}
        break unless line
        puts line
      rescue Timeout::Error
        STDERR.puts "+++++++ running for #{(Time.now - start).round} seconds"
      end
    end
  end
end

def run_command cmd
  puts cmd
  puts `#{cmd}`
end

def get_parameters
  params = {
    shadowingArgs: nil,
    sources: [],
    entries: [],
    dry: false,
    compile: true,
    product: true,
    verify: true,
    time: nil,
    unroll: nil,
    printModel: nil,
    full_self_comp: nil,
    a: 'a.bpl',
    b: 'b.bpl',
    clang_options: ["-I#{__dir__}/../include"]
  }

  OptionParser.new do |opts|
    opts.banner = "Usage: #{File.basename $0} [options] FILE(s)"

    opts.on("-h", "--help", "Show this message") do |v|
      puts opts
      exit
    end

    opts.on('-n', "--dry-run", "Just pretend.") do |d|
      params[:dry] = d
    end

    opts.on('-e', '--shadowingArgs args', "The args to the shadowing pass.") do |p|
      params[:shadowingArgs] = p
    end
    
    opts.on('-e', '--entry-point PROC', "Entry-point procedures.") do |p|
      params[:entries] << p
    end

    opts.on('--clang-options STRING', "Flags to pass to clang.") do |s|
      params[:clang_options] << s unless s.empty?
    end

    opts.on('-t', '--time-limit SECONDS', "Time limit.") do |t|
      params[:time] = t
    end

    opts.on('--print-model flag', "Print the Model.") do |u|
      params[:printModel] = u
    end

    opts.on('--full-self-comp flag', "Perform full self composition.") do |u|
      params[:full_self_comp] = u
    end

    opts.on('-u', '--unroll-limit NUMBER', "Unroll limit.") do |u|
      params[:unroll] = u
    end

    opts.on('-l', '--loop-limit NUMBER', "Loop analysis limit.") do |l|
      params[:loop] = l
    end

    opts.on('-a FILE', "Intermediate file after Boogie translation.") do |f|
      params[:a] = f
    end

    opts.on('-b FILE', "Intermediate file after product construction.") do |f|
      params[:b] = f
    end

    opts.separator ""
    opts.separator "phase selection"

    opts.on('--[no-]compile', "Compile the input program?") do |p|
      params[:compile] = p
    end

    opts.on('--[no-]product', "Do the product construction?") do |p|
      params[:product] = p
    end

    opts.on('--[no-]verify', "Do the verification?") do |p|
      params[:verify] = p
    end

    opts.on('--timing-analysis', "Perform timing analysis") do |p|
      params[:timing] = p
    end


  end.parse!
  params[:sources] = ARGV

  raise "Input FILES required; see --help." if params[:sources].empty?
  params[:sources].each do |f|
    raise "File #{f} not found." unless File.exists? f
  end
  if params[:compile]
    raise "Entry-points PROCS required see --help." if params[:entries].empty?
  else
    raise "Too many input FILES given." if params[:sources].count > 1
  end

  params[:a] = params[:sources].first unless params[:compile]
  params[:b] = params[:a] unless params[:product]

  return params
end

begin
  params = get_parameters
  echo = params[:dry] ? "echo" : ""

  inputs = params[:sources]
  temp_files = []

  SPECIAL_FUNCTIONS = [
    "__SMACK",
    "__VERIFIER",
    "__builtin",
    "llvm\.",
    "public_in",
    "public_out",
    "declassified_out",
    "public_invariant",
    "benign",
    "__disjoint_regions"
  ]

  INLINE_ASM_PATTERN = /\basm\b/
  UNDEFINED_PATTERN = /\bdeclare\b .* @(?!(#{SPECIAL_FUNCTIONS * "|"}))([^(]*)/

  if params[:compile]
    flags = ["-t"]
    flags << "--clang-options=\"#{params[:clang_options] * " "}\"" if params[:clang_options].any?
    flags << "--loop-limit #{params[:loop]}" if params[:loop]
    flags << "--verifier boogie"
    flags << "--entry-points #{params[:entries] * ","}"
    flags << "-ll #{params[:a]}.ll"
    flags << "-bpl #{params[:a]}"
    flags << "--timing-annotations" if params[:timing]
    puts `which clang`
    puts `which llvm-link`
    puts `clang --version`
    puts `llvm-link --version`
    puts "#{flags * " "} #{params[:sources] * " "}"
    puts `#{echo} smack #{flags * " "} #{params[:sources] * " "}`
    raise "failed to compile #{params[:sources] * ", "}" unless $?.success?
    warn "warning: module contains inline assembly" \
      if File.readlines("#{params[:a]}.ll").grep(INLINE_ASM_PATTERN).any?

    ufs = File.readlines("#{params[:a]}.ll")
        .map{|s| s.match UNDEFINED_PATTERN}
        .compact
        .map{|m| m[2]}

    warn "warning: module contains undefined functions: #{ufs * ", "}" if ufs.any?
  end

  if params[:product]
    full = if params[:full_self_comp] then "full" else "selective" end
    shadowingArgs = "self_comp_mode=#{full}"
    shadowingArgs = "#{shadowingArgs},#{params[:shadowingArgs]}" if params[:shadowingArgs]
    shadowingArgs.gsub(/\s+/, "") #remove whitespace from the args if necessary
    flags = []
    flags << "--cost-modeling" if params[:timing]
    flags << "--shadowing #{shadowingArgs}"
    flags << "--pruning"
    puts `#{echo} bam -q -i #{params[:a]} #{flags * " "} -o #{params[:b]}`
    raise "failed to construct product program" unless $?.success?
  end

  if params[:verify]
    flags = []
    flags << "/printModel 4" if params[:printModel]
    flags << "/doModSetAnalysis"
    flags << "/loopUnroll:#{params[:unroll]}" if params[:unroll]
    flags << "/timeLimit:#{params[:time]}" if params[:time]
    warn "warning: only unrolling up to #{params[:unroll]}" if params[:unroll]
    run_command_with_heartbeat(30, "#{echo} boogie #{flags * " "} #{params[:b]}")
    #raise "failed to process product program" unless $?.success?
  end

rescue Interrupt
  puts "Got interrupt."

rescue => e
  puts "#{e}"
  exit(-1)

ensure

end
