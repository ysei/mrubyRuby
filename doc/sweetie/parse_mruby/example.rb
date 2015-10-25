
class A
  def b
    print("helloworld")
  end
  def self.c
    print("helloworld")
  end
  def d
    "Hello, World!"
  end
  def e(a1, a2 = 1, *a3, a4, &a5)
    p a1, a2, a3, a4, a5
    print(d)
  end
  class << self
    def f
      print("Hello, World!")
    end
  end
end

class B < A
  def b
    if (true)
      print(true)
    else
      print(false)
    end
  end
end

class C
  nil
end

$global = "helloworld\n"
def g
  local = "Hello, World!\n"
  print(local)
  $global = local
end

print($global)
g()
print($global)


