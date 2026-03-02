class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "0.2.0"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.2.0/ssrok-darwin-arm64"
      sha256 "b99d205603fa98b0a97f6f0ed0b5177e119c7ccf30a30b59570af0a341111ba6"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.2.0/ssrok-darwin-amd64"
      sha256 "379ea139e01cfcb93377e865e457099ac6b0b1f1ad570687626d044e91ae5850"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.2.0/ssrok-linux-arm64"
      sha256 "593d37824b67f6acb93620418e9e6f5dcaa2c0015486ba44ea711deab7233bfb"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.2.0/ssrok-linux-amd64"
      sha256 "b1525993fb4e22ad3f9546bbc59c63a5017bd1dfa424ab5566790559da89a09e"
    end
  end

  def install
    bin.install Dir["*"].first => "ssrok"
  end

  test do
    system "#{bin}/ssrok", "--help"
  end
end
