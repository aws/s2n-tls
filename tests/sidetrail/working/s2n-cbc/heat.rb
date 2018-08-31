require 'nyaplot'
require 'nyaplot3d'

colors = Nyaplot::Colors.qual

f = File.open(ARGV[0], "r")
x=[]
y=[]
x_s=[]
y_s=[]
f.each_line do |li|
  m = /\$l.shadow@(.*) -> (.*)/.match(li)
  if m
    x.push(Integer(m[1]))
    y.push(Integer(m[2]))
  end
  m = /\$l@(.*) -> (.*)/.match(li)
  if m
    x_s.push(Integer(m[1]))
    y_s.push(Integer(m[2]))
  end

end
#puts x

plot1 = Nyaplot::Plot.new
sc1 = plot1.add(:scatter, x, y)
plot2 = Nyaplot::Plot.new
sc2 = plot2.add(:scatter, x_s, y_s)


frame = Nyaplot::Frame.new
frame.add(plot1)
frame.add(plot2)
frame.export_html("multiple_pane.html")
