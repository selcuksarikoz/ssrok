class Ssrok < Formula
  desc "Blazing fast secure reverse proxy tunnel"
  homepage "https://github.com/selcuksarikoz/ssrok"
  version "0.1.13"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.13/ssrok-darwin-arm64"
      sha256 "e6c5b136021181aafa7158c913eb6397581b3ea923ccfb2ad2344fb8e5428ee3"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.13/ssrok-darwin-amd64"
      sha256 "6f089a3f2cbd646fb2a88dd33190218d07221bf1d3ccbd659ac112665978e249"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.13/ssrok-linux-arm64"
      sha256 "0572ec7364aa5c6c832c5bbb9324b40472607eab8338f8579de02f3b859daf8f"
    else
      url "https://github.com/selcuksarikoz/ssrok/releases/download/v0.1.13/ssrok-linux-amd64"
      sha256 "f04781a21db323432ccc0eb670cdad4d3a0870051eb257563d5d0a0d12af4e7d"
    end
  end

  def install
    bin.install Dir["*"].first => "ssrok"
  end

  test do
    system "#{bin}/ssrok", "--help"
  end
end
