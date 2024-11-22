with Ada.Containers.Indefinite_Holders;
with Ada.Containers.Indefinite_Vectors;

with Ada.Streams;
use Ada.Streams;

with GNAT.Sockets;

package TLS is
   ---------------
   -- TLS Types --
   ---------------

   type Unsigned_16 is mod 2**16 with
     Size => 16;

   procedure Write_Unsigned_16 (Stream : not null access Root_Stream_Type'Class; Item : Unsigned_16);
   procedure Read_Unsigned_16 (Stream : not null access Root_Stream_Type'Class; Item : out Unsigned_16);

   for Unsigned_16'Read use Read_Unsigned_16;
   for Unsigned_16'Write use Write_Unsigned_16;

   type Record_Types is
     (HANDSHAKE) with
     Size => 8;
   for Record_Types use
     (HANDSHAKE => 16#16#);

   type Protocol_Versions is
     (TLS_10,
      TLS_11,
      TLS_12,
      TLS_13,
      UNKNOWN) with
     Size => 16;
   for Protocol_Versions use
     (TLS_10  => 16#03_01#,
      TLS_11  => 16#03_02#,
      TLS_12  => 16#03_03#,
      TLS_13  => 16#03_04#,
      UNKNOWN => 16#FF_FF#);

   procedure Write_Protocol_Version (Stream : not null access Root_Stream_Type'Class; Item : Protocol_Versions);
   procedure Read_Protocol_Version (Stream : not null access Root_Stream_Type'Class; Item : out Protocol_Versions);

   for Protocol_Versions'Read use Read_Protocol_Version;
   for Protocol_Versions'Write use Write_Protocol_Version;

   type Protocol_Versions_Array is
     array (Natural range <>)
     of Protocol_Versions;

   package Protocol_Versions_Array_Holders is new Ada.Containers.Indefinite_Holders (Protocol_Versions_Array);

   type TLS_Record is
     abstract tagged record
        Record_Type             : Record_Types;
        Record_Protocol_Version : Protocol_Versions := TLS_10; --  Middlebox compatibility
        Record_Length           : Unsigned_16;                 --  Solved automatically when 'Writing
     end record;

   procedure Write_TLS_Record (Stream : not null access Root_Stream_Type'Class; Item : TLS_Record);
   procedure Read_TLS_Record (Stream : not null access Root_Stream_Type'Class; Item : out TLS_Record);

   for TLS_Record'Read use Read_TLS_Record;
   for TLS_Record'Write use Write_TLS_Record;

     ---------------------
     -- Record Variants --
     -- HANDSHAKE       --
     ---------------------

   type Unsigned_24 is mod 2**24 with
     Size => 24;

   procedure Write_Unsigned_24 (Stream : not null access Root_Stream_Type'Class; Item : Unsigned_24);
   procedure Read_Unsigned_24 (Stream : not null access Root_Stream_Type'Class; Item : out Unsigned_24);

   for Unsigned_24'Read use Read_Unsigned_24;
   for Unsigned_24'Write use Write_Unsigned_24;

   type Handshake_Message_Types is
     (CLIENT_HELLO,
      SERVER_HELLO) with
     Size => 8;
   for Handshake_Message_Types use
     (CLIENT_HELLO => 16#01#,
      SERVER_HELLO => 16#02#);

   type Handshake_Record is
     abstract new TLS_Record with record
        Message_Type      : Handshake_Message_Types;
        Message_Length    : Unsigned_24;
        Extensions_Length : Unsigned_16;
     end record;

   procedure Write_Handshake_Record (Stream : not null access Root_Stream_Type'Class; Item : Handshake_Record);
   procedure Read_Handshake_Record (Stream : not null access Root_Stream_Type'Class; Item : out Handshake_Record);

   for Handshake_Record'Read use Read_Handshake_Record;
   for Handshake_Record'Write use Write_Handshake_Record;

     ---------------------
     -- Record Variants --
     -- HANDSHAKE       --
     -- Client Hello    --
     ---------------------

   type Unsigned_8 is mod 2**8 with
     Size => 8;

   package String_Holders is new Ada.Containers.Indefinite_Holders (String);

   type Cipher_Suites is
     (TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
      TLS_AES_128_GCM_SHA256,
      TLS_AES_256_GCM_SHA384,
      TLS_CHACHA20_POLY1305_SHA256,
      UNKNOWN) with
     Size => 16;

   for Cipher_Suites use
     (TLS_EMPTY_RENEGOTIATION_INFO_SCSV => 16#00_FF#,
      TLS_AES_128_GCM_SHA256            => 16#13_01#,
      TLS_AES_256_GCM_SHA384            => 16#13_02#,
      TLS_CHACHA20_POLY1305_SHA256      => 16#13_03#,
      UNKNOWN                           => 16#FF_FF#);

   procedure Write_Cipher_Suite (Stream : not null access Root_Stream_Type'Class; Item : Cipher_Suites);
   procedure Read_Cipher_Suite (Stream : not null access Root_Stream_Type'Class; Item : out Cipher_Suites);

   for Cipher_Suites'Read use Read_Cipher_Suite;
   for Cipher_Suites'Write use Write_Cipher_Suite;

   type Cipher_Suite_Array is
     array (Unsigned_16 range <>)
     of Cipher_Suites;

   package Cipher_Suite_Holders is new Ada.Containers.Indefinite_Holders (Cipher_Suite_Array);

   type Compression_Methods is
     (NONE,
      UNKNOWN) with
     Size => 8;

   for Compression_Methods use
     (NONE    => 16#00#,
      UNKNOWN => 16#FF#);

   procedure Read_Compression_Method (Stream : not null access Root_Stream_Type'Class; Item : out Compression_Methods);

   for Compression_Methods'Read use Read_Compression_Method;

   type Compression_Method_Array is
     array (Unsigned_8 range <>)
     of Compression_Methods;

   package Compression_Method_Holders is new Ada.Containers.Indefinite_Holders (Compression_Method_Array);

     --  https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml

   type Extension_Types is
     (SERVER_NAME,
      SUPPORTED_GROUPS,
      EC_POINT_FORMATS,
      SIGNATURE_ALGORITHMS,
      ALPN,
      PADDING,
      ENCRYPT_THEN_MAC,
      EXTENDED_MASTER_SECRET,
      SESSION_TICKET,
      SUPPORTED_VERSIONS,
      PSK_KEY_EXCHANGE_MODES,
      POST_HANDSHAKE_AUTH,
      KEY_SHARE,
      UNKNOWN) with
     Size => 16;

   for Extension_Types use
     (SERVER_NAME            => 16#00_00#,
      SUPPORTED_GROUPS       => 16#00_0A#,
      EC_POINT_FORMATS       => 16#00_0B#,
      SIGNATURE_ALGORITHMS   => 16#00_0D#,
      ALPN                   => 16#00_10#,
      PADDING                => 16#00_15#,
      ENCRYPT_THEN_MAC       => 16#00_16#,
      EXTENDED_MASTER_SECRET => 16#00_17#,
      SESSION_TICKET         => 16#00_23#,
      SUPPORTED_VERSIONS     => 16#00_2B#,
      PSK_KEY_EXCHANGE_MODES => 16#00_2D#,
      POST_HANDSHAKE_AUTH    => 16#00_31#,
      KEY_SHARE              => 16#00_33#,
      UNKNOWN                => 16#FF_FF#);

   type Elliptic_Curve_Groups is
     (SECP192R1,
      SECP224R1,
      SECP256R1,
      SECP381R1,
      SECP521R1,
      X25519,
      X448,
      UNKNOWN) with
     Size => 16;

   for Elliptic_Curve_Groups use
     (SECP192R1 => 16#00_13#,
      SECP224R1 => 16#00_15#,
      SECP256R1 => 16#00_17#,
      SECP381R1 => 16#00_18#,
      SECP521R1 => 16#00_19#,
      X25519    => 16#00_1D#,
      X448      => 16#00_1E#,
      UNKNOWN   => 16#FF_FF#);

   procedure Write_Elliptic_Curve_Group (Stream : not null access Root_Stream_Type'Class; Item : Elliptic_Curve_Groups);
   procedure Read_Elliptic_Curve_Group (Stream : not null access Root_Stream_Type'Class; Item : out Elliptic_Curve_Groups);

   for Elliptic_Curve_Groups'Read use Read_Elliptic_Curve_Group;
   for Elliptic_Curve_Groups'Write use Write_Elliptic_Curve_Group;

   type Elliptic_Curve_Public_Key is
     record
        Group : Elliptic_Curve_Groups;
        Key   : String_Holders.Holder;
     end record;

   type Elliptic_Curve_Public_Key_Array is
     array (Natural range <>)
     of Elliptic_Curve_Public_Key;

   package Elliptic_Curve_Public_Key_Array_Holders is new Ada.Containers.Indefinite_Holders (Elliptic_Curve_Public_Key_Array);

   type Extension (Extension_Type : Extension_Types) is
     record
        Assigned_Value : Unsigned_16 := Extension_Types'(UNKNOWN)'Enum_Rep;
        Size           : Unsigned_16 := 0;
        Size_Assigned  : Boolean     := False;
        From_Server    : Boolean     := False;
        case Extension_Type is
           when KEY_SHARE =>
              Keys : Elliptic_Curve_Public_Key_Array_Holders.Holder;

           when SUPPORTED_VERSIONS =>
              Versions : Protocol_Versions_Array_Holders.Holder;

           when others =>
              Data : String_Holders.Holder;
        end case;
     end record;

   procedure Assign_Extension_Size (Item : in out Extension);

   procedure Write_Extension (Stream : not null access Root_Stream_Type'Class; Item : Extension);
   procedure Read_Extension (Stream : not null access Root_Stream_Type'Class; Item : out Extension);
   function Read_Extension (Stream : not null access Root_Stream_Type'Class) return Extension;

   for Extension'Input use Read_Extension;
   for Extension'Read use Read_Extension;
   for Extension'Write use Write_Extension;

   package Extension_Vectors is new Ada.Containers.Indefinite_Vectors (Natural, Extension);

   type Handshake_Client_Hello_Record is
     new Handshake_Record with record
        Client_Protocol_Version    : Protocol_Versions;
        Client_Random              : String (1 .. 32);
        Client_Session_ID          : String_Holders.Holder;
        Client_Cipher_Suites       : Cipher_Suite_Holders.Holder;
        Client_Compression_Methods : Compression_Method_Holders.Holder;
        Client_Extensions          : Extension_Vectors.Vector;
     end record;

   --   procedure Write_Handshake_Client_Hello_Record (Stream : not null access Root_Stream_Type'Class; Item : Handshake_Client_Hello_Record);
   procedure Read_Handshake_Client_Hello_Record (Stream : not null access Root_Stream_Type'Class; Item : out Handshake_Client_Hello_Record);

   for Handshake_Client_Hello_Record'Read use Read_Handshake_Client_Hello_Record;
     --   for Handshake_Client_Hello_Record'Write use Write_Handshake_Client_Hello_Record;

     ---------------------
     -- Record Variants --
     -- HANDSHAKE       --
     -- Server Hello    --
     ---------------------

   type Handshake_Server_Hello_Record is
     new Handshake_Record with record
        Server_Protocol_Version   : Protocol_Versions   := TLS_12; --  Middlebox compatibility
        Server_Random             : String (1 .. 32);
        Server_Session_ID         : String_Holders.Holder;
        Server_Cipher_Suite       : Cipher_Suites;
        Server_Compression_Method : Compression_Methods := NONE; --  https://en.wikipedia.org/wiki/CRIME
        Server_Extensions         : Extension_Vectors.Vector;
     end record;

   procedure Assign_Sizes_For_Handshake_Server_Hello_Record (Item : in out Handshake_Server_Hello_Record);

   procedure Write_Handshake_Server_Hello_Record (Stream : not null access Root_Stream_Type'Class; Item : Handshake_Server_Hello_Record);
   --   procedure Read_Handshake_Server_Hello_Record (Stream : not null access Root_Stream_Type'Class; Item : out Handshake_Server_Hello_Record);

   --   for Handshake_Server_Hello_Record'Read use Read_Handshake_Server_Hello_Record;
   for Handshake_Server_Hello_Record'Write use Write_Handshake_Server_Hello_Record;

   ------------------------
   -- TLS Stream/Wrapper --
   -- Types              --
   ------------------------

   type Stream_Access is access all Ada.Streams.Root_Stream_Type'Class;

   type TLS_Stream_Type is limited private;

   type TLS_Stream_Access is access all TLS_Stream_Type;

   ------------------------
   -- TLS Stream/Wrapper --
   -- Operations         --
   ------------------------

   function Wrap_Stream (Stream : Stream_Access) return TLS_Stream_Access;

   function Stream (TLS_Stream : TLS_Stream_Access) return Stream_Access;
   function Stream_Raw (TLS_Stream : TLS_Stream_Access) return Stream_Access;
   procedure Enable_TLS (TLS_Stream : in out TLS_Stream_Access);
   procedure Disable_TLS (TLS_Stream : in out TLS_Stream_Access);

   TLS_State_Error : exception;

private
   ------------------------
   -- TLS Stream/Wrapper --
   ------------------------

   type TLS_Stream_Type is
     new Root_Stream_Type with record
        Raw_Stream : Stream_Access;
        TLS_Active : Boolean;
     end record;

   overriding
   procedure Read (Stream : in out TLS_Stream_Type; Item : out Stream_Element_Array; Last : out Stream_Element_Offset);

   overriding
   procedure Write (Stream : in out TLS_Stream_Type; Item : Stream_Element_Array);
end TLS;
