with Ada.Streams;
use Ada.Streams;

with GNAT.Sockets;

package TLS is
   type Stream_Access is access all Ada.Streams.Root_Stream_Type'Class;

   type Stream_Wrapper is limited private;

   type Stream_Wrapper_Access is access Stream_Wrapper;

   function Wrap_Stream (Stream : Stream_Access) return Stream_Wrapper_Access;

   function Stream (Wrapper : Stream_Wrapper) return Stream_Access;
   function Stream_Raw (Wrapper : Stream_Wrapper) return Stream_Access;
   procedure Enable_TLS (Wrapper : in out Stream_Wrapper);
   procedure Disable_TLS (Wrapper : in out Stream_Wrapper);

private
   type TLS_Stream_Type is
     new Root_Stream_Type with record
        Raw_Stream : Stream_Access;
     end record;

   type TLS_Stream_Access is not null access TLS_Stream_Type;

   overriding
   procedure Read (Stream : in out TLS_Stream_Type; Item : out Stream_Element_Array; Last : out Stream_Element_Offset);

   overriding
   procedure Write (Stream : in out TLS_Stream_Type; Item : Stream_Element_Array);

   type Stream_Wrapper is
     record
        TLS_Stream : TLS_Stream_Access;
        TLS_Active : Boolean;
     end record;
end TLS;
