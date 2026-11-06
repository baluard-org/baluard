#!/usr/bin/env ruby
# Convert macOS SDK .tbd stubs to the tapi-tbd v4 / arm64-macos shape zig 0.14 accepts.
# Walks reexported-libraries recursively and merges arm64-flavored export symbols.
require 'yaml'
require 'fileutils'

SDK = ARGV[0] or abort "usage: tbd-convert.rb <SDK> <out-dir> <fw|lib>"
OUT = ARGV[1]
kind = ARGV[2]
seen = {}

def convert(doc)
  exports = doc['exports'] || []
  out = { symbols: [], weak: [], classes: [], ivars: [] }
  exports.each do |e|
    targets = e['targets'] || []
    # SDK 27 usr/lib tbds (libz, libiconv, libcharset) are x86_64-only; their
    # ABI is identical on arm64 at runtime, so any macos target converts.
    next unless targets.any? { |t| t.include?('macos') }
    out[:symbols] |= (e['symbols'] || [])
    out[:weak] |= (e['weak-symbols'] || [])
    out[:classes] |= (e['objc-classes'] || [])
    out[:ivars] |= (e['objc-ivars'] || [])
  end
  out.each_value { |v| v.sort! }
  { conv: out, install_name: doc['install-name'] }
end

def walk(path, sdk, seen)
  return nil if path.nil? || seen[path]
  seen[path] = true
  doc = (YAML.load_file(path, aliases: true) rescue nil)
  return nil unless doc.is_a?(Hash) && doc['tbd-version']
  merged = { conv: { symbols: [], weak: [], classes: [], ivars: [] }, install_name: doc['install-name'] }
  c = convert(doc)
  %i[symbols weak classes ivars].each do |f|
    merged[:conv][f] |= c[:conv][f]
  end
  (doc['reexported-libraries'] || []).each do |rel|
    paths = rel.is_a?(Hash) ? (rel['libraries'] || []) : [rel]
    paths.each do |p|
      next unless p.is_a?(String)
      cand = [File.join(sdk, p), File.join(sdk, 'System/Library/Frameworks', p),
              File.join(sdk, 'usr/lib', p)].uniq.flat_map { |q| [q, "#{q}.tbd"] }
      src = cand.find { |q| File.exist?(q) }
      next unless src
      sub = walk(src, sdk, seen)
      next unless sub
      %i[symbols weak classes ivars].each do |f|
        merged[:conv][f] |= sub[:conv][f]
      end
    end
  end
  merged
rescue StandardError => e
  warn "RAISE #{path}: #{e.class}: #{e.message}"
  nil
end

def emit(out_path, install_name, conv)
  export_entry = { 'targets' => ['arm64-macos'] }
  export_entry['symbols'] = conv[:symbols] unless conv[:symbols].empty?
  export_entry['weak-symbols'] = conv[:weak] unless conv[:weak].empty?
  export_entry['objc-classes'] = conv[:classes] unless conv[:classes].empty?
  export_entry['objc-ivars'] = conv[:ivars] unless conv[:ivars].empty?
  body = {
    'tbd-version' => 4,
    'targets' => ['arm64-macos'],
    'install-name' => install_name,
    'exports' => [export_entry],
  }
  text = YAML.dump(body).sub(/\A---\s*\n/, "--- !tapi-tbd\n")
  File.write(out_path, text)
end

if kind == 'fw'
  fw_root = File.join(SDK, 'System/Library/Frameworks')
  ok = 0
  Dir.glob(File.join(fw_root, '*.framework', '*.tbd')).sort.each do |src|
    fw_name = File.basename(File.dirname(src), '.framework')
    m = walk(src, SDK, {})
    unless m
      warn "WALKFAIL #{src}"
      next
    end
    out_dir = File.join(OUT, "#{fw_name}.framework")
    FileUtils.mkdir_p(out_dir)
    emit(File.join(out_dir, "#{fw_name}.tbd"), m[:install_name], m[:conv])
    ok += 1
  end
  puts "fw ok=#{ok}"
else
  ok = 0
  Dir.glob(File.join(SDK, 'usr/lib', '*.tbd')).sort.each do |src|
    m = walk(src, SDK, {})
    next unless m
    emit(File.join(OUT, File.basename(src)), m[:install_name], m[:conv])
    ok += 1
  end
  puts "lib ok=#{ok}"
end
