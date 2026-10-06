"""Small, pure layout policies and native Tk flow layout."""
from modules.ui_theme import PALETTE as UI_COLORS

def flow_positions(width,item_widths,gap=8):
    """Wrap rows using widget requested widths; suitable for scaled fonts/DPI."""
    width=max(1,int(width));row=0;col=0;used=0;positions=[]
    for requested in item_widths:
        size=min(width,max(1,int(requested)))
        if col and used+gap+size>width:
            row+=1;col=0;used=0
        positions.append((row,col))
        used+=size+(gap if col else 0);col+=1
    return positions


class SidebarPolicy:
    def __init__(self,threshold=1150):
        self.threshold=threshold;self.compact=None;self.visible=True
    def resize(self,width):
        compact=width<self.threshold
        if compact!=self.compact:
            self.compact=compact;self.visible=not compact
        return self.visible
    def toggle(self):
        self.visible=not self.visible;return self.visible


class FlowRow:
    """Use independent row containers so unequal rows do not share column widths."""
    def __init__(self,frame,widgets,gap=8,row_style='Card.TFrame'):
        self.frame=frame;self.widgets=widgets;self.gap=gap;self.last=None;self.rows=[];self.row_style=row_style
        self.pending=None;self.destroyed=False
        frame.bind('<Configure>',self.layout,add='+')
        frame.bind('<Destroy>',self.on_destroy,add='+')
        for widget in widgets:widget.bind('<Configure>',self.layout,add='+')
        self.apply([(0,col) for col in range(len(widgets))])
    def apply(self,positions):
        from tkinter import ttk
        needed=max((row for row,col in positions),default=0)+1
        for widget in self.widgets:widget.grid_forget()
        while len(self.rows)<needed:
            self.rows.append(ttk.Frame(self.frame,style=self.row_style))
        for index,row_frame in enumerate(self.rows):
            if index<needed:row_frame.pack(fill='x')
            else:row_frame.pack_forget()
        for widget,(row,col) in zip(self.widgets,positions):
            widget.grid(in_=self.rows[row],row=0,column=col,sticky='w',padx=(0,self.gap),pady=3)
        self.last=positions
    def layout(self,event):
        # Changing geometry inside Configure can re-enter Tk's active grid layout.
        # Coalesce notifications and wait until that layout pass has returned.
        if not self.destroyed and self.pending is None:
            self.pending=self.frame.after_idle(self.apply_pending)
    def apply_pending(self):
        self.pending=None
        if self.destroyed:return
        positions=flow_positions(self.frame.winfo_width(),[widget.winfo_reqwidth()+self.gap for widget in self.widgets],self.gap)
        if positions!=self.last:self.apply(positions)
    def on_destroy(self,event):
        if event.widget is self.frame:
            self.destroyed=True
            if self.pending is not None:
                self.frame.after_cancel(self.pending)
                self.pending=None


class AdaptiveForm:
    """Independent field cards: two columns on wide containers, one when narrow."""
    def __init__(self,frame,fields,threshold=700):
        self.frame=frame;self.fields=fields;self.threshold=threshold;self.last=None
        frame.bind('<Configure>',self.layout,add='+')
        self.apply(2)
    def apply(self,columns):
        for column in (0,1):self.frame.columnconfigure(column,weight=1 if column<columns else 0)
        for index,field in enumerate(self.fields):
            field.grid(row=index//columns,column=index%columns,sticky='ew',padx=6,pady=4)
        self.last=columns
    def layout(self,event):
        columns=2 if event.width>=self.threshold else 1
        if columns!=self.last:self.apply(columns)


class ScrollablePanel:
    """Scrollable page body; inner width tracks available canvas width."""
    def __init__(self,parent):
        import tkinter as tk
        from tkinter import ttk
        self.frame=ttk.Frame(parent);self.frame.pack(fill='both',expand=True)
        self.frame.rowconfigure(0,weight=1);self.frame.columnconfigure(0,weight=1)
        self.canvas=tk.Canvas(self.frame,highlightthickness=0,bg=UI_COLORS['background'])
        scroll=ttk.Scrollbar(self.frame,orient='vertical',command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scroll.set)
        self.canvas.grid(row=0,column=0,sticky='nsew');scroll.grid(row=0,column=1,sticky='ns')
        self.body=ttk.Frame(self.canvas,padding=12)
        window=self.canvas.create_window((0,0),window=self.body,anchor='nw')
        self.canvas.bind('<Configure>',lambda event:self.canvas.itemconfigure(window,width=event.width))
        self.body.bind('<Configure>',lambda event:self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        # Only canvas/body scrolling, no application-wide mouse-wheel binding.
        for widget in (self.canvas,self.body):widget.bind('<MouseWheel>',lambda event:self.canvas.yview_scroll(-int(event.delta/120),'units'))


def cancel_page_timers(container):
    """Cancel callbacks owned by a page subtree; root service timers keep running."""
    from tkinter import TclError
    owners={}
    def collect(widget):
        for command in getattr(widget,'_tclCommands',None) or ():owners[command]=widget
        for child in widget.winfo_children():collect(child)
    collect(container)
    for timer in container.tk.call('after','info'):
        try:
            info=container.tk.call('after','info',timer)
            script=str(info[0])
            if script in owners:owners[script].after_cancel(timer)
        except TclError:pass
