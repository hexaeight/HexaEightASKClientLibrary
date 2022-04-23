Imports System
Imports System.Net
Imports System.IO
Imports System.Text
Imports System.Numerics
Imports System.Security.Cryptography
Imports Newtonsoft.Json
Imports JsonWriter = Newtonsoft.Json.JsonWriter
Imports NETCore.Encrypt
Imports System.Net.Http
Imports System.Net.Http.Headers

Namespace HexaEight

    Public Class HESession
        Public Property Id As String
        Public Property EncryptedID As String
        Public Property Pin As String
        Public Property IsActive As Boolean
        Public Property TimeStamp As Int64
        Public Property AFToken As Int64
        Public Property User As String
        Public Property UserRespData As String

    End Class


    Public Class ASKClient

        Private LoginToken As String
        Private Resource As String
        Private TokenSecret As String
        Private RapidAPIKey As String
        Private Hexa8RAhost As String
        Private PublicKey As String
        Private RSAKeyPair As RSAParameters
        Private DBLocation As String
        Private SafeKey As String


        Private Get_sharedkey_usingtoken_url As String
        Private Get_sharedkey_usingname_url As String
        Private Get_presharedkey_usingname_url As String
        Private Get_clientappsharedkey_usingname_url As String


        Private Function PerformHttpWebRequest(ByVal bearertoken As String, ByVal httpurl As String, ByVal Body As String, ByVal contenttype As String) As String
            Dim httpWebRequest = CType(WebRequest.Create(httpurl), HttpWebRequest)
            'httpWebRequest.ServerCertificateValidationCallback = Function() True

            If contenttype = "" Then
                httpWebRequest.ContentType = "application/text"
            Else
                httpWebRequest.ContentType = "application/json"
            End If

            httpWebRequest.Method = "POST"
            httpWebRequest.Headers.Add("Authorization", "Bearer " & bearertoken)

            Using streamWriter = New StreamWriter(httpWebRequest.GetRequestStream())
                Dim input As String = Body.ToString()
                streamWriter.Write(input)
                streamWriter.Flush()
                streamWriter.Close()
            End Using

            Try
                Dim httpResponse = CType(httpWebRequest.GetResponse(), HttpWebResponse)

                If httpResponse.StatusCode.ToString() = "OK" Then
                    Return New StreamReader(httpResponse.GetResponseStream()).ReadToEnd().ToString()
                Else
                    Return ""
                End If

            Catch ex As Exception
                Console.WriteLine("Exception Occured while performing HTTP Request" & ex.Message)
                Return ""
            End Try
        End Function

        Public Function EncryptRawUsingUAK(ByVal BinaryData As Byte(), ByVal UAK As String, ByVal AsymetricSharedkey As String) As Byte()
            Try
                Dim Preauthkeys = AsymetricSharedkey.Split(":")(0) + ":" + AsymetricSharedkey.Split(":")(1)
                If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then
                    Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                    Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                    Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                    Dim msgbytes As Byte() = Convert2BinaryHEBytes(BinaryData)
                    Return CreateV3EncryptedRequestForUser(msgbytes, GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(UAK)), New BigInteger(Convert.FromBase64String(AsymetricSharedkey.Split(":")(2))))
                Else
                    Return New Byte() {}
                End If
            Catch ex As Exception
                Return New Byte() {}
            End Try
        End Function

        Public Function DecryptRawUsingUAK(ByVal EncryptedBinaryData As Byte(), ByVal UAK As String, ByVal AsymetricSharedkey As String) As Byte()
            Try
                Dim Preauthkeys = AsymetricSharedkey.Split(":")(0) + ":" + AsymetricSharedkey.Split(":")(1)
                If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then
                    Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                    Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                    Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                    Dim DecryptedMessage As Byte() = DecryptV3EncryptedRawFromUser(EncryptedBinaryData, GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(UAK)), New BigInteger(Convert.FromBase64String(AsymetricSharedkey.Split(":")(2))))
                    If (DecryptedMessage.Length > 0) Then
                        Return ConvertFromBinaryHEBytes(DecryptedMessage)
                    Else
                        Return New Byte() {}
                    End If
                Else
                    Return New Byte() {}
                End If
            Catch ex As Exception
                Return New Byte() {}
            End Try
        End Function



        Public Function EncryptRaw(ByVal BinaryData As Byte(), ByVal AsymetricSharedkey As String) As Byte()
            Try
                Dim Preauthkeys = AsymetricSharedkey.Split(":")(0) + ":" + AsymetricSharedkey.Split(":")(1)
                If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then

                    Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                    Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                    Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                    Dim msgbytes As Byte() = Convert2BinaryHEBytes(BinaryData)
                    Return CreateV3EncryptedRequestForDestination(msgbytes, GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(AsymetricSharedkey.Split(":")(2))))
                Else
                    Return New Byte() {}
                End If
            Catch ex As Exception
                Return New Byte() {}
            End Try
        End Function

        Public Function DecryptRaw(ByVal EncryptedBinaryData As Byte(), ByVal AsymetricSharedkey As String) As Byte()
            Try
                Dim Preauthkeys = AsymetricSharedkey.Split(":")(0) + ":" + AsymetricSharedkey.Split(":")(1)
                If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then
                    Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                    Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                    Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                    Dim DecryptedMessage As Byte() = DecryptV3EncryptedRawMessage(EncryptedBinaryData, GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(AsymetricSharedkey.Split(":")(2))))
                    If (DecryptedMessage.Length > 0) Then
                        Return ConvertFromBinaryHEBytes(DecryptedMessage)
                    Else
                        Return New Byte() {}
                    End If
                Else
                    Return New Byte() {}
                End If
            Catch ex As Exception
                Return New Byte() {}
            End Try
        End Function



        Private Function Convert2BinaryHEBytes(ByVal messagebytes As Byte()) As Byte()
            Try

                Dim processedbytes As New List(Of Byte())
                Dim nextbytesA As UInt16
                Dim nextbytesB As UInt16
                Dim nextbytes As BigInteger
                Dim divident As BigInteger
                Dim quotient As UInt16
                Dim finalbytes(63) As Byte
                Dim initbytes(1) As Byte
                Dim qbytes(2) As Byte
                Dim keycounter = New Random().Next(32768, 65536)
                'keycounter = 65534
                qbytes = BitConverter.GetBytes(keycounter)
                initbytes(0) = qbytes(0)
                initbytes(1) = qbytes(1)
                processedbytes.Add(initbytes)
                Dim bytectr As Int64 = 0
                Dim finalctr As Integer = 0
                Dim origctr As Integer = 0
                Dim origbytes(59) As Byte
                bytectr = 0
                While bytectr <= messagebytes.Length - 1
                    If bytectr + 60 > messagebytes.Length Then
                        Array.Copy(messagebytes, bytectr, origbytes, 0, messagebytes.Length - bytectr)
                    Else
                        Array.Copy(messagebytes, bytectr, origbytes, 0, 60)
                    End If
                    origctr = 0
                    finalctr = 0
                    While origctr < 60
                        Array.Clear(qbytes, 0, 2)
                        If (origctr = 0) Then
                            nextbytesA = BitConverter.ToUInt16(origbytes, origctr)
                            nextbytesB = BitConverter.ToUInt16(origbytes, origctr + 2)
                            nextbytes = BigInteger.Add(BigInteger.Multiply(nextbytesA, 65536), nextbytesB)
                            divident = BigInteger.DivRem(nextbytes, keycounter, quotient)
                            qbytes = BitConverter.GetBytes(quotient)
                            finalbytes(finalctr) = qbytes(0)
                            finalbytes(finalctr + 1) = qbytes(1)
                            finalctr += 2
                            origctr += 4
                        Else
                            nextbytesB = BitConverter.ToUInt16(origbytes, origctr)
                            nextbytes = BigInteger.Add(BigInteger.Multiply(divident, 65536), nextbytesB)
                            divident = BigInteger.DivRem(nextbytes, keycounter, quotient)
                            qbytes = BitConverter.GetBytes(quotient)
                            finalbytes(finalctr) = qbytes(0)
                            finalbytes(finalctr + 1) = qbytes(1)
                            finalctr += 2
                            origctr += 2
                        End If
                        keycounter += 1
                        If keycounter = 65536 Then
                            keycounter = 32768
                        End If

                    End While

                    If finalctr = 58 Then
                        While divident > 0 And finalctr < 64
                            Array.Clear(qbytes, 0, 2)
                            nextbytes = divident
                            divident = BigInteger.DivRem(nextbytes, 65536, quotient)
                            qbytes = BitConverter.GetBytes(quotient)
                            finalbytes(finalctr) = qbytes(0)
                            finalbytes(finalctr + 1) = qbytes(1)
                            finalctr += 2
                        End While
                        If finalctr <> 64 Then
                            finalctr = 64
                        End If
                    End If
                    If divident = 0 And finalctr = 64 Then
                        Dim pbytes As Byte() = New Byte(63) {}
                        Array.Copy(finalbytes, pbytes, finalbytes.Length)
                        processedbytes.Add(pbytes)
                        Array.Clear(finalbytes, 0, finalbytes.Length)
                        Array.Clear(origbytes, 0, origbytes.Length)
                        finalctr = 0
                    End If

                    bytectr += 60
                End While

                Return (From bytes In processedbytes From x In bytes Select x).ToArray()

            Catch ex As Exception
                Return Nothing
            End Try

        End Function

        Private Function ConvertFromBinaryHEBytes(ByVal messagebytes As Byte()) As Byte()
            Try
                Dim bytectr As Int64 = 2
                Dim initbytes(1) As Byte
                Dim qbytes(2) As Byte
                Dim finalbytes(63) As Byte
                Dim keycounter As Integer
                keycounter = BitConverter.ToUInt16(messagebytes, 0)
                Dim nextkeycounter As Integer = keycounter + 29
                Dim oquotient As UInt16
                Dim quotient As UInt16
                Dim finalcnt As Integer
                Dim divident As BigInteger
                Dim odivident As BigInteger
                Dim origbytes(59) As Byte
                Dim origctr As Integer
                Dim processedbytes As New List(Of Byte())

                If nextkeycounter > 65536 Then
                    nextkeycounter = (nextkeycounter Mod 32768) + 32768
                End If


                bytectr = 2
                While bytectr < messagebytes.Length
                    Array.Copy(messagebytes, bytectr, finalbytes, 0, 64)
                    finalcnt = 62
                    divident = 0
                    quotient = 0
                    odivident = 0
                    oquotient = 0
                    Array.Clear(qbytes, 0, 2)
                    origctr = 58
                    While finalcnt >= 0
                        If finalcnt > 57 Then
                            quotient = BitConverter.ToUInt16(finalbytes, finalcnt)
                            divident = BigInteger.Add(BigInteger.Multiply(divident, 65536), quotient)
                            finalcnt = finalcnt - 2
                        Else
                            If finalcnt = 0 Then
                                quotient = BitConverter.ToUInt16(finalbytes, finalcnt)
                                divident = BigInteger.Add(BigInteger.Multiply(odivident, nextkeycounter - 1), quotient)
                                odivident = BigInteger.DivRem(divident, 65536, oquotient)
                                qbytes = BitConverter.GetBytes(oquotient)
                                origbytes(origctr) = qbytes(0)
                                origbytes(origctr + 1) = qbytes(1)
                                origctr = origctr - 2
                                oquotient = odivident
                                qbytes = BitConverter.GetBytes(oquotient)
                                origbytes(origctr) = qbytes(0)
                                origbytes(origctr + 1) = qbytes(1)
                                origctr = origctr - 2
                                nextkeycounter = nextkeycounter - 1
                                If nextkeycounter = 32768 Then
                                    nextkeycounter = 65536
                                End If
                                Exit While
                            Else
                                quotient = BitConverter.ToUInt16(finalbytes, finalcnt)

                                divident = BigInteger.Add(BigInteger.Multiply(divident, nextkeycounter - 1), quotient)
                                odivident = BigInteger.DivRem(divident, 65536, oquotient)
                                qbytes = BitConverter.GetBytes(oquotient)
                                origbytes(origctr) = qbytes(0)
                                origbytes(origctr + 1) = qbytes(1)
                                finalcnt = finalcnt - 2
                                origctr = origctr - 2
                                If finalcnt > 0 Then
                                    divident = odivident
                                End If

                            End If
                            nextkeycounter = nextkeycounter - 1

                            If nextkeycounter = 32768 Then
                                nextkeycounter = 65536
                            End If
                        End If
                    End While
                    If finalcnt = 0 Then
                        Dim pbytes As Byte() = New Byte(59) {}
                        Array.Copy(origbytes, pbytes, origbytes.Length)
                        processedbytes.Add(pbytes)
                        Array.Clear(origbytes, 0, origbytes.Length)
                    End If

                    bytectr = bytectr + 64
                    nextkeycounter = nextkeycounter + 58
                    If nextkeycounter > 65536 Then
                        nextkeycounter = (nextkeycounter Mod 32768) + 32768
                    End If
                End While
                Return (From bytes In processedbytes From x In bytes Select x).ToArray()
            Catch ex As Exception
                Return Nothing
            End Try
        End Function



        Private Function Convert2QuickHEBytes(ByVal message As String) As Byte()
            Try

                Dim processedbytes As New List(Of Byte())
                Dim messagebytes = System.Text.Encoding.UTF8.GetBytes(message)
                Dim nextbytesA As UInt16
                Dim nextbytesB As UInt16
                Dim nextbytes As BigInteger
                Dim divident As BigInteger
                Dim quotient As UInt16
                Dim finalbytes(63) As Byte
                Dim initbytes(1) As Byte
                Dim qbytes(2) As Byte
                Dim keycounter = New Random().Next(32768, 65536)
                'keycounter = 65534
                qbytes = BitConverter.GetBytes(keycounter)
                initbytes(0) = qbytes(0)
                initbytes(1) = qbytes(1)
                processedbytes.Add(initbytes)
                Dim bytectr As Int64 = 0
                Dim finalctr As Integer = 0
                Dim origctr As Integer = 0
                Dim origbytes(59) As Byte
                bytectr = 0
                While bytectr < messagebytes.Length - 1
                    If bytectr + 60 > messagebytes.Length Then
                        Array.Copy(messagebytes, bytectr, origbytes, 0, messagebytes.Length - bytectr)
                    Else
                        Array.Copy(messagebytes, bytectr, origbytes, 0, 60)
                    End If
                    origctr = 0
                    finalctr = 0
                    While origctr < 60
                        Array.Clear(qbytes, 0, 2)
                        If (origctr = 0) Then
                            nextbytesA = BitConverter.ToUInt16(origbytes, origctr)
                            nextbytesB = BitConverter.ToUInt16(origbytes, origctr + 2)
                            nextbytes = BigInteger.Add(BigInteger.Multiply(nextbytesA, 65536), nextbytesB)
                            divident = BigInteger.DivRem(nextbytes, keycounter, quotient)
                            qbytes = BitConverter.GetBytes(quotient)
                            finalbytes(finalctr) = qbytes(0)
                            finalbytes(finalctr + 1) = qbytes(1)
                            finalctr += 2
                            origctr += 4
                        Else
                            nextbytesB = BitConverter.ToUInt16(origbytes, origctr)
                            nextbytes = BigInteger.Add(BigInteger.Multiply(divident, 65536), nextbytesB)
                            divident = BigInteger.DivRem(nextbytes, keycounter, quotient)
                            qbytes = BitConverter.GetBytes(quotient)
                            finalbytes(finalctr) = qbytes(0)
                            finalbytes(finalctr + 1) = qbytes(1)
                            finalctr += 2
                            origctr += 2
                        End If
                        keycounter += 1
                        If keycounter = 65536 Then
                            keycounter = 32768
                        End If

                    End While

                    If finalctr = 58 Then
                        While divident > 0 And finalctr < 64
                            Array.Clear(qbytes, 0, 2)
                            nextbytes = divident
                            divident = BigInteger.DivRem(nextbytes, 65536, quotient)
                            qbytes = BitConverter.GetBytes(quotient)
                            finalbytes(finalctr) = qbytes(0)
                            finalbytes(finalctr + 1) = qbytes(1)
                            finalctr += 2
                        End While
                        If finalctr <> 64 Then
                            finalctr = 64
                        End If
                    End If
                    If divident = 0 And finalctr = 64 Then
                        Dim pbytes As Byte() = New Byte(63) {}
                        Array.Copy(finalbytes, pbytes, finalbytes.Length)
                        processedbytes.Add(pbytes)
                        Array.Clear(finalbytes, 0, finalbytes.Length)
                        Array.Clear(origbytes, 0, origbytes.Length)
                        finalctr = 0
                    End If

                    bytectr += 60
                End While

                Return (From bytes In processedbytes From x In bytes Select x).ToArray()

            Catch ex As Exception
                Return Nothing
            End Try

        End Function

        Private Function ConvertFromQuickHEBytes(ByVal messagebytes As Byte()) As Byte()
            Try
                Dim bytectr As Int64 = 2
                Dim initbytes(1) As Byte
                Dim qbytes(2) As Byte
                Dim finalbytes(63) As Byte
                Dim keycounter As Integer
                keycounter = BitConverter.ToUInt16(messagebytes, 0)
                Dim nextkeycounter As Integer = keycounter + 29
                Dim oquotient As UInt16
                Dim quotient As UInt16
                Dim finalcnt As Integer
                Dim divident As BigInteger
                Dim odivident As BigInteger
                Dim origbytes(59) As Byte
                Dim origctr As Integer
                Dim processedbytes As New List(Of Byte())

                If nextkeycounter > 65536 Then
                    nextkeycounter = (nextkeycounter Mod 32768) + 32768
                End If


                bytectr = 2
                While bytectr < messagebytes.Length
                    Array.Copy(messagebytes, bytectr, finalbytes, 0, 64)
                    finalcnt = 62
                    divident = 0
                    quotient = 0
                    odivident = 0
                    oquotient = 0
                    Array.Clear(qbytes, 0, 2)
                    origctr = 58
                    While finalcnt >= 0
                        If finalcnt > 57 Then
                            quotient = BitConverter.ToUInt16(finalbytes, finalcnt)
                            divident = BigInteger.Add(BigInteger.Multiply(divident, 65536), quotient)
                            finalcnt = finalcnt - 2
                        Else
                            If finalcnt = 0 Then
                                quotient = BitConverter.ToUInt16(finalbytes, finalcnt)
                                divident = BigInteger.Add(BigInteger.Multiply(odivident, nextkeycounter - 1), quotient)
                                odivident = BigInteger.DivRem(divident, 65536, oquotient)
                                qbytes = BitConverter.GetBytes(oquotient)
                                origbytes(origctr) = qbytes(0)
                                origbytes(origctr + 1) = qbytes(1)
                                origctr = origctr - 2
                                oquotient = odivident
                                qbytes = BitConverter.GetBytes(oquotient)
                                origbytes(origctr) = qbytes(0)
                                origbytes(origctr + 1) = qbytes(1)
                                origctr = origctr - 2
                                nextkeycounter = nextkeycounter - 1
                                If nextkeycounter = 32768 Then
                                    nextkeycounter = 65536
                                End If
                                Exit While
                            Else
                                quotient = BitConverter.ToUInt16(finalbytes, finalcnt)

                                divident = BigInteger.Add(BigInteger.Multiply(divident, nextkeycounter - 1), quotient)
                                odivident = BigInteger.DivRem(divident, 65536, oquotient)
                                qbytes = BitConverter.GetBytes(oquotient)
                                origbytes(origctr) = qbytes(0)
                                origbytes(origctr + 1) = qbytes(1)
                                finalcnt = finalcnt - 2
                                origctr = origctr - 2
                                If finalcnt > 0 Then
                                    divident = odivident
                                End If

                            End If
                            nextkeycounter = nextkeycounter - 1

                            If nextkeycounter = 32768 Then
                                nextkeycounter = 65536
                            End If
                        End If
                    End While
                    If finalcnt = 0 Then
                        Dim pbytes As Byte() = New Byte(59) {}
                        Array.Copy(origbytes, pbytes, origbytes.Length)
                        processedbytes.Add(pbytes)
                        Array.Clear(origbytes, 0, origbytes.Length)
                    End If

                    bytectr = bytectr + 64
                    nextkeycounter = nextkeycounter + 58
                    If nextkeycounter > 65536 Then
                        nextkeycounter = (nextkeycounter Mod 32768) + 32768
                    End If
                End While
                Return (From bytes In processedbytes From x In bytes Select x).ToArray()
                'Console.WriteLine(System.Text.Encoding.UTF8.GetString(data))
            Catch ex As Exception
                Return Nothing
            End Try
        End Function


        Private Function CreateV3EncryptedRequestForUser(ByVal messagedata As Byte(), ByVal PasswordKeys As BigInteger, ByVal Token1Keys As BigInteger, ByVal Token2Keys As BigInteger, ByVal uak As BigInteger, ByVal ressharedkeys As BigInteger) As Byte()
            Try
                Dim keycounter As Integer
                keycounter = BitConverter.ToUInt16(messagedata, 0)
                If keycounter > 65536 Then
                    keycounter = (keycounter Mod 32768) + 32768
                End If
                Dim qbytes(1) As Byte
                qbytes = BitConverter.GetBytes(keycounter)
                Dim destinationdata(messagedata.Length - 1) As Byte
                destinationdata(0) = qbytes(0)
                destinationdata(1) = qbytes(1)
                Dim ReminderPK0 As BigInteger
                Dim ReminderTK1 As BigInteger
                Dim ReminderTK2 As BigInteger
                Dim ReminderUAK As BigInteger
                Dim ReminderRSK As BigInteger

                Dim encrypteddata As Integer
                Dim finalcnt As Integer = 0
                Dim bytectr As Int64
                bytectr = 2
                finalcnt = 0
                Dim bitdata As UInt16
                While bytectr < messagedata.Length
                    If finalcnt = 64 Then
                        finalcnt = 0
                    End If
                    bitdata = BitConverter.ToUInt16(messagedata, bytectr)
                    If (finalcnt > 57) Then
                        ReminderPK0 = BigInteger.Remainder(PasswordKeys, 65536)
                        ReminderTK1 = BigInteger.Remainder(Token1Keys, 65536)
                        ReminderTK2 = BigInteger.Remainder(Token2Keys, 65536)
                        ReminderUAK = BigInteger.Remainder(uak, 65536)
                        ReminderRSK = BigInteger.Remainder(ressharedkeys, 65536)

                        If ReminderPK0 < 0 Then
                            ReminderPK0 = (ReminderPK0 + 65536) Mod 65536
                        End If
                        If ReminderTK1 < 0 Then
                            ReminderTK1 = (ReminderTK1 + 65536) Mod 65536
                        End If
                        If ReminderTK2 < 0 Then
                            ReminderTK2 = (ReminderTK2 + 65536) Mod 65536
                        End If
                        If ReminderUAK < 0 Then
                            ReminderUAK = (ReminderUAK + 65536) Mod 65536
                        End If
                        If ReminderRSK < 0 Then
                            ReminderRSK = (ReminderRSK + 65536) Mod 65536
                        End If


                        encrypteddata = ((ReminderPK0 * ReminderTK1) + ReminderTK2 + bitdata + ReminderUAK + ReminderRSK) Mod 65536
                        If encrypteddata < 0 Then
                            encrypteddata += 65536
                        End If
                        'While (encrypteddata < 0)
                        'encrypteddata += 65536
                        'End While
                    Else
                        If bitdata < keycounter Then
                            ReminderPK0 = BigInteger.Remainder(PasswordKeys, keycounter)
                            ReminderTK1 = BigInteger.Remainder(Token1Keys, keycounter)
                            ReminderTK2 = BigInteger.Remainder(Token2Keys, keycounter)
                            ReminderUAK = BigInteger.Remainder(uak, keycounter)
                            ReminderRSK = BigInteger.Remainder(ressharedkeys, keycounter)

                            If ReminderPK0 < 0 Then
                                ReminderPK0 = (ReminderPK0 + keycounter) Mod keycounter
                            End If
                            If ReminderTK1 < 0 Then
                                ReminderTK1 = (ReminderTK1 + keycounter) Mod keycounter
                            End If
                            If ReminderTK2 < 0 Then
                                ReminderTK2 = (ReminderTK2 + keycounter) Mod keycounter
                            End If
                            If ReminderUAK < 0 Then
                                ReminderUAK = (ReminderUAK + keycounter) Mod keycounter
                            End If
                            If ReminderRSK < 0 Then
                                ReminderRSK = (ReminderRSK + keycounter) Mod keycounter
                            End If


                            encrypteddata = ((ReminderPK0 * ReminderTK1) + ReminderTK2 + bitdata + ReminderUAK + ReminderRSK) Mod keycounter
                            If encrypteddata < 0 Then
                                encrypteddata += keycounter
                            End If
                            'While (encrypteddata < 0)
                            'encrypteddata += keycounter
                            'End While

                        Else
                            Return Nothing
                        End If
                    End If
                    qbytes = BitConverter.GetBytes(encrypteddata)
                    destinationdata(bytectr) = qbytes(0)
                    destinationdata(bytectr + 1) = qbytes(1)
                    keycounter += 1
                    If keycounter = 65536 Then
                        keycounter = 32768
                    End If

                    bytectr += 2
                    finalcnt += 2
                End While
                Return destinationdata
            Catch ex As Exception
                Return Nothing
            End Try
        End Function

        Private Function DecryptV3EncryptedRawFromUser(ByVal messagedata As Byte(), ByVal PasswordKeys As BigInteger, ByVal Token1Keys As BigInteger, ByVal Token2Keys As BigInteger, ByVal uak As BigInteger, ByVal userSharedKeys As BigInteger) As Byte()
            Try
                Dim keycounter As Integer
                keycounter = BitConverter.ToUInt16(messagedata, 0)
                If keycounter > 65536 Then
                    keycounter = (keycounter Mod 32768) + 32768
                End If
                Dim qbytes(1) As Byte
                qbytes = BitConverter.GetBytes(keycounter)
                Dim destinationdata(messagedata.Length - 1) As Byte
                destinationdata(0) = qbytes(0)
                destinationdata(1) = qbytes(1)
                Dim ReminderPK0 As BigInteger
                Dim ReminderTK1 As BigInteger
                Dim ReminderTK2 As BigInteger
                Dim ReminderUAK As BigInteger
                Dim ReminderSKY As BigInteger

                Dim encrypteddata As Integer
                Dim finalcnt As Integer = 0
                Dim bytectr As Int64
                bytectr = 2
                finalcnt = 0
                Dim bitdata As UInt16
                While bytectr < messagedata.Length
                    If finalcnt = 64 Then
                        finalcnt = 0
                    End If
                    bitdata = BitConverter.ToUInt16(messagedata, bytectr)
                    If (finalcnt > 57) Then
                        ReminderPK0 = BigInteger.Remainder(PasswordKeys, 65536)
                        ReminderTK1 = BigInteger.Remainder(Token1Keys, 65536)
                        ReminderTK2 = BigInteger.Remainder(Token2Keys, 65536)
                        ReminderUAK = BigInteger.Remainder(uak, 65536)
                        ReminderSKY = BigInteger.Remainder(userSharedKeys, 65536)
                        If ReminderPK0 < 0 Then
                            ReminderPK0 = (ReminderPK0 + 65536) Mod 65536
                        End If
                        If ReminderTK1 < 0 Then
                            ReminderTK1 = (ReminderTK1 + 65536) Mod 65536
                        End If
                        If ReminderTK2 < 0 Then
                            ReminderTK2 = (ReminderTK2 + 65536) Mod 65536
                        End If
                        If ReminderUAK < 0 Then
                            ReminderUAK = (ReminderUAK + 65536) Mod 65536
                        End If
                        If ReminderSKY < 0 Then
                            ReminderSKY = (ReminderSKY + 65536) Mod 65536
                        End If

                        encrypteddata = (bitdata - (ReminderUAK + ReminderSKY) - ((ReminderPK0 * ReminderTK1) + ReminderTK2)) Mod 65536
                        If encrypteddata < 0 Then
                            encrypteddata += 65536
                        End If
                        'While (encrypteddata < 0)
                        'encrypteddata += 65536
                        'End While

                    Else
                        If bitdata < keycounter Then
                            ReminderPK0 = BigInteger.Remainder(PasswordKeys, keycounter)
                            ReminderTK1 = BigInteger.Remainder(Token1Keys, keycounter)
                            ReminderTK2 = BigInteger.Remainder(Token2Keys, keycounter)
                            ReminderUAK = BigInteger.Remainder(uak, keycounter)
                            ReminderSKY = BigInteger.Remainder(userSharedKeys, keycounter)

                            If ReminderPK0 < 0 Then
                                ReminderPK0 = (ReminderPK0 + keycounter) Mod keycounter
                            End If
                            If ReminderTK1 < 0 Then
                                ReminderTK1 = (ReminderTK1 + keycounter) Mod keycounter
                            End If
                            If ReminderTK2 < 0 Then
                                ReminderTK2 = (ReminderTK2 + keycounter) Mod keycounter
                            End If
                            If ReminderUAK < 0 Then
                                ReminderUAK = (ReminderUAK + keycounter) Mod keycounter
                            End If
                            If ReminderSKY < 0 Then
                                ReminderSKY = (ReminderSKY + keycounter) Mod keycounter
                            End If


                            encrypteddata = (bitdata - (ReminderUAK + ReminderSKY) - ((ReminderPK0 * ReminderTK1) + ReminderTK2)) Mod keycounter
                            If encrypteddata < 0 Then
                                encrypteddata += keycounter
                            End If

                            'While (encrypteddata < 0)
                            'encrypteddata += keycounter
                            'End While

                        Else
                            Return New Byte() {}
                        End If
                    End If
                    qbytes = BitConverter.GetBytes(encrypteddata)
                    destinationdata(bytectr) = qbytes(0)
                    destinationdata(bytectr + 1) = qbytes(1)
                    keycounter += 1
                    If keycounter = 65536 Then
                        keycounter = 32768
                    End If

                    bytectr += 2
                    finalcnt += 2
                End While
                Return destinationdata
            Catch ex As Exception
                Console.WriteLine(ex.Message)
                Return New Byte() {}
            End Try
        End Function


        Private Function DecryptV3EncryptedRequestFromUser(ByVal messagedata As Byte(), ByVal PasswordKeys As BigInteger, ByVal Token1Keys As BigInteger, ByVal Token2Keys As BigInteger, ByVal userSharedKeys As BigInteger) As String
            Try
                Dim keycounter As Integer
                keycounter = BitConverter.ToUInt16(messagedata, 0)
                If keycounter > 65536 Then
                    keycounter = (keycounter Mod 32768) + 32768
                End If
                Dim qbytes(1) As Byte
                qbytes = BitConverter.GetBytes(keycounter)
                Dim destinationdata(messagedata.Length - 1) As Byte
                destinationdata(0) = qbytes(0)
                destinationdata(1) = qbytes(1)
                Dim ReminderPK0 As BigInteger
                Dim ReminderTK1 As BigInteger
                Dim ReminderTK2 As BigInteger
                Dim ReminderSKY As BigInteger

                Dim encrypteddata As Integer
                Dim finalcnt As Integer = 0
                Dim bytectr As Int64
                bytectr = 2
                finalcnt = 0
                Dim bitdata As UInt16
                While bytectr < messagedata.Length
                    If finalcnt = 64 Then
                        finalcnt = 0
                    End If
                    bitdata = BitConverter.ToUInt16(messagedata, bytectr)
                    If (finalcnt > 57) Then
                        ReminderPK0 = BigInteger.Remainder(PasswordKeys, 65536)
                        ReminderTK1 = BigInteger.Remainder(Token1Keys, 65536)
                        ReminderTK2 = BigInteger.Remainder(Token2Keys, 65536)
                        ReminderSKY = BigInteger.Remainder(userSharedKeys, 65536)
                        If ReminderPK0 < 0 Then
                            ReminderPK0 = (ReminderPK0 + 65536) Mod 65536
                        End If
                        If ReminderTK1 < 0 Then
                            ReminderTK1 = (ReminderTK1 + 65536) Mod 65536
                        End If
                        If ReminderTK2 < 0 Then
                            ReminderTK2 = (ReminderTK2 + 65536) Mod 65536
                        End If
                        If ReminderSKY < 0 Then
                            ReminderSKY = (ReminderSKY + 65536) Mod 65536
                        End If

                        encrypteddata = (bitdata - ReminderSKY - ((ReminderPK0 * ReminderTK1) + ReminderTK2)) Mod 65536
                        'If encrypteddata < 0 Then
                        'encrypteddata += 65536
                        'End If
                        While (encrypteddata < 0)
                            encrypteddata += 65536
                        End While

                    Else
                        If bitdata < keycounter Then
                            ReminderPK0 = BigInteger.Remainder(PasswordKeys, keycounter)
                            ReminderTK1 = BigInteger.Remainder(Token1Keys, keycounter)
                            ReminderTK2 = BigInteger.Remainder(Token2Keys, keycounter)
                            ReminderSKY = BigInteger.Remainder(userSharedKeys, keycounter)

                            If ReminderPK0 < 0 Then
                                ReminderPK0 = (ReminderPK0 + keycounter) Mod keycounter
                            End If
                            If ReminderTK1 < 0 Then
                                ReminderTK1 = (ReminderTK1 + keycounter) Mod keycounter
                            End If
                            If ReminderTK2 < 0 Then
                                ReminderTK2 = (ReminderTK2 + keycounter) Mod keycounter
                            End If
                            If ReminderSKY < 0 Then
                                ReminderSKY = (ReminderSKY + keycounter) Mod keycounter
                            End If


                            encrypteddata = (bitdata - ReminderSKY - ((ReminderPK0 * ReminderTK1) + ReminderTK2)) Mod keycounter
                            'If encrypteddata < 0 Then
                            'encrypteddata += keycounter
                            'End If

                            While (encrypteddata < 0)
                                encrypteddata += keycounter
                            End While

                        Else
                            Return Nothing
                        End If
                    End If
                    qbytes = BitConverter.GetBytes(encrypteddata)
                    destinationdata(bytectr) = qbytes(0)
                    destinationdata(bytectr + 1) = qbytes(1)
                    keycounter += 1
                    If keycounter = 65536 Then
                        keycounter = 32768
                    End If

                    bytectr += 2
                    finalcnt += 2
                End While
                Dim responsedata As New Object
                Dim hebytes As Byte()
                hebytes = ConvertFromQuickHEBytes(destinationdata)
                responsedata = Newtonsoft.Json.JsonConvert.DeserializeObject(System.Text.Encoding.UTF8.GetString(hebytes).Replace(vbNullChar, ""))
                Return responsedata.ToString()
            Catch ex As Exception
                Console.WriteLine(ex.Message)
                Return Nothing
            End Try
        End Function


        Private Function DecryptV3EncryptedRequestUsingUAK(ByVal messagedata As Byte(), ByVal PasswordKeys As BigInteger, ByVal Token1Keys As BigInteger, ByVal Token2Keys As BigInteger, ByVal uak As BigInteger, ByVal userSharedKeys As BigInteger) As String
            Try
                Dim keycounter As Integer
                keycounter = BitConverter.ToUInt16(messagedata, 0)
                If keycounter > 65536 Then
                    keycounter = (keycounter Mod 32768) + 32768
                End If
                Dim qbytes(1) As Byte
                qbytes = BitConverter.GetBytes(keycounter)
                Dim destinationdata(messagedata.Length - 1) As Byte
                destinationdata(0) = qbytes(0)
                destinationdata(1) = qbytes(1)
                Dim ReminderPK0 As BigInteger
                Dim ReminderTK1 As BigInteger
                Dim ReminderTK2 As BigInteger
                Dim ReminderUAK As BigInteger
                Dim ReminderSKY As BigInteger

                Dim encrypteddata As Integer
                Dim finalcnt As Integer = 0
                Dim bytectr As Int64
                bytectr = 2
                finalcnt = 0
                Dim bitdata As UInt16
                While bytectr < messagedata.Length
                    If finalcnt = 64 Then
                        finalcnt = 0
                    End If
                    bitdata = BitConverter.ToUInt16(messagedata, bytectr)
                    If (finalcnt > 57) Then
                        ReminderPK0 = BigInteger.Remainder(PasswordKeys, 65536)
                        ReminderTK1 = BigInteger.Remainder(Token1Keys, 65536)
                        ReminderTK2 = BigInteger.Remainder(Token2Keys, 65536)
                        ReminderUAK = BigInteger.Remainder(uak, 65536)
                        ReminderSKY = BigInteger.Remainder(userSharedKeys, 65536)
                        If ReminderPK0 < 0 Then
                            ReminderPK0 = (ReminderPK0 + 65536) Mod 65536
                        End If
                        If ReminderTK1 < 0 Then
                            ReminderTK1 = (ReminderTK1 + 65536) Mod 65536
                        End If
                        If ReminderTK2 < 0 Then
                            ReminderTK2 = (ReminderTK2 + 65536) Mod 65536
                        End If
                        If ReminderUAK < 0 Then
                            ReminderUAK = (ReminderUAK + 65536) Mod 65536
                        End If
                        If ReminderSKY < 0 Then
                            ReminderSKY = (ReminderSKY + 65536) Mod 65536
                        End If

                        encrypteddata = (bitdata - (ReminderUAK + ReminderSKY) - ((ReminderPK0 * ReminderTK1) + ReminderTK2)) Mod 65536
                        If encrypteddata < 0 Then
                            encrypteddata += 65536
                        End If
                        'While (encrypteddata < 0)
                        'encrypteddata += 65536
                        'End While

                    Else
                        If bitdata < keycounter Then
                            ReminderPK0 = BigInteger.Remainder(PasswordKeys, keycounter)
                            ReminderTK1 = BigInteger.Remainder(Token1Keys, keycounter)
                            ReminderTK2 = BigInteger.Remainder(Token2Keys, keycounter)
                            ReminderUAK = BigInteger.Remainder(uak, keycounter)
                            ReminderSKY = BigInteger.Remainder(userSharedKeys, keycounter)

                            If ReminderPK0 < 0 Then
                                ReminderPK0 = (ReminderPK0 + keycounter) Mod keycounter
                            End If
                            If ReminderTK1 < 0 Then
                                ReminderTK1 = (ReminderTK1 + keycounter) Mod keycounter
                            End If
                            If ReminderTK2 < 0 Then
                                ReminderTK2 = (ReminderTK2 + keycounter) Mod keycounter
                            End If
                            If ReminderUAK < 0 Then
                                ReminderUAK = (ReminderUAK + keycounter) Mod keycounter
                            End If
                            If ReminderSKY < 0 Then
                                ReminderSKY = (ReminderSKY + keycounter) Mod keycounter
                            End If


                            encrypteddata = (bitdata - (ReminderUAK + ReminderSKY) - ((ReminderPK0 * ReminderTK1) + ReminderTK2)) Mod keycounter
                            If encrypteddata < 0 Then
                                encrypteddata += keycounter
                            End If

                            'While (encrypteddata < 0)
                            'encrypteddata += keycounter
                            'End While

                        Else
                            Return Nothing
                        End If
                    End If
                    qbytes = BitConverter.GetBytes(encrypteddata)
                    destinationdata(bytectr) = qbytes(0)
                    destinationdata(bytectr + 1) = qbytes(1)
                    keycounter += 1
                    If keycounter = 65536 Then
                        keycounter = 32768
                    End If

                    bytectr += 2
                    finalcnt += 2
                End While
                Dim responsedata As New Object
                Dim hebytes As Byte()
                hebytes = ConvertFromQuickHEBytes(destinationdata)
                responsedata = Newtonsoft.Json.JsonConvert.DeserializeObject(System.Text.Encoding.UTF8.GetString(hebytes).Replace(vbNullChar, ""))
                Return responsedata.ToString()
            Catch ex As Exception
                Console.WriteLine(ex.Message)
                Return Nothing
            End Try
        End Function


        Private Function CreateV3EncryptedRequestForDestination(ByVal messagedata As Byte(), ByVal PasswordKeys As BigInteger, ByVal Token1Keys As BigInteger, ByVal Token2Keys As BigInteger, ByVal SharedKeys As BigInteger) As Byte()
            Try
                Dim keycounter As Integer
                keycounter = BitConverter.ToUInt16(messagedata, 0)
                If keycounter > 65536 Then
                    keycounter = (keycounter Mod 32768) + 32768
                End If
                Dim qbytes(1) As Byte
                qbytes = BitConverter.GetBytes(keycounter)
                Dim destinationdata(messagedata.Length - 1) As Byte
                destinationdata(0) = qbytes(0)
                destinationdata(1) = qbytes(1)
                Dim ReminderPK0 As BigInteger
                Dim ReminderTK1 As BigInteger
                Dim ReminderTK2 As BigInteger
                Dim ReminderSKY As BigInteger

                Dim encrypteddata As Integer
                Dim finalcnt As Integer = 0
                Dim bytectr As Int64
                bytectr = 2
                finalcnt = 0
                Dim bitdata As UInt16
                While bytectr < messagedata.Length
                    If finalcnt = 64 Then
                        finalcnt = 0
                    End If
                    bitdata = BitConverter.ToUInt16(messagedata, bytectr)
                    If (finalcnt > 57) Then
                        ReminderPK0 = BigInteger.Remainder(PasswordKeys, 65536)
                        ReminderTK1 = BigInteger.Remainder(Token1Keys, 65536)
                        ReminderTK2 = BigInteger.Remainder(Token2Keys, 65536)
                        ReminderSKY = BigInteger.Remainder(SharedKeys, 65536)
                        If ReminderPK0 < 0 Then
                            ReminderPK0 = (ReminderPK0 + 65536) Mod 65536
                        End If
                        If ReminderTK1 < 0 Then
                            ReminderTK1 = (ReminderTK1 + 65536) Mod 65536
                        End If
                        If ReminderTK2 < 0 Then
                            ReminderTK2 = (ReminderTK2 + 65536) Mod 65536
                        End If
                        If ReminderSKY < 0 Then
                            ReminderSKY = (ReminderSKY + 65536) Mod 65536
                        End If

                        encrypteddata = ((ReminderPK0 * ReminderTK1) + ReminderTK2 + bitdata + ReminderSKY) Mod 65536
                        If encrypteddata < 0 Then
                            encrypteddata += 65536
                        End If

                    Else
                        If bitdata < keycounter Then
                            ReminderPK0 = BigInteger.Remainder(PasswordKeys, keycounter)
                            ReminderTK1 = BigInteger.Remainder(Token1Keys, keycounter)
                            ReminderTK2 = BigInteger.Remainder(Token2Keys, keycounter)
                            ReminderSKY = BigInteger.Remainder(SharedKeys, keycounter)

                            If ReminderPK0 < 0 Then
                                ReminderPK0 = (ReminderPK0 + keycounter) Mod keycounter
                            End If
                            If ReminderTK1 < 0 Then
                                ReminderTK1 = (ReminderTK1 + keycounter) Mod keycounter
                            End If
                            If ReminderTK2 < 0 Then
                                ReminderTK2 = (ReminderTK2 + keycounter) Mod keycounter
                            End If
                            If ReminderSKY < 0 Then
                                ReminderSKY = (ReminderSKY + keycounter) Mod keycounter
                            End If


                            encrypteddata = ((ReminderPK0 * ReminderTK1) + ReminderTK2 + bitdata + ReminderSKY) Mod keycounter
                            If encrypteddata < 0 Then
                                encrypteddata += keycounter
                            End If
                        Else
                            Return Nothing
                        End If
                    End If
                    qbytes = BitConverter.GetBytes(encrypteddata)
                    destinationdata(bytectr) = qbytes(0)
                    destinationdata(bytectr + 1) = qbytes(1)
                    keycounter += 1
                    If keycounter = 65536 Then
                        keycounter = 32768
                    End If

                    bytectr += 2
                    finalcnt += 2
                End While
                Return destinationdata
            Catch ex As Exception
                Return Nothing
            End Try
        End Function

        Private Function DecryptV3EncryptedRequestFromDestination(ByVal messagedata As Byte(), ByVal PasswordKeys As BigInteger, ByVal Token1Keys As BigInteger, ByVal Token2Keys As BigInteger, ByVal SharedKeys As BigInteger) As String
            Try
                Dim keycounter As Integer
                keycounter = BitConverter.ToUInt16(messagedata, 0)
                If keycounter > 65536 Then
                    keycounter = (keycounter Mod 32768) + 32768
                End If
                Dim qbytes(1) As Byte
                qbytes = BitConverter.GetBytes(keycounter)
                Dim destinationdata(messagedata.Length - 1) As Byte
                destinationdata(0) = qbytes(0)
                destinationdata(1) = qbytes(1)
                Dim ReminderPK0 As BigInteger
                Dim ReminderTK1 As BigInteger
                Dim ReminderTK2 As BigInteger
                Dim ReminderSKY As BigInteger

                Dim encrypteddata As Integer
                Dim finalcnt As Integer = 0
                Dim bytectr As Int64
                bytectr = 2
                finalcnt = 0
                Dim bitdata As UInt16
                While bytectr < messagedata.Length
                    If finalcnt = 64 Then
                        finalcnt = 0
                    End If
                    bitdata = BitConverter.ToUInt16(messagedata, bytectr)
                    If (finalcnt > 57) Then
                        ReminderPK0 = BigInteger.Remainder(PasswordKeys, 65536)
                        ReminderTK1 = BigInteger.Remainder(Token1Keys, 65536)
                        ReminderTK2 = BigInteger.Remainder(Token2Keys, 65536)
                        ReminderSKY = BigInteger.Remainder(SharedKeys, 65536)
                        If ReminderPK0 < 0 Then
                            ReminderPK0 = (ReminderPK0 + 65536) Mod 65536
                        End If
                        If ReminderTK1 < 0 Then
                            ReminderTK1 = (ReminderTK1 + 65536) Mod 65536
                        End If
                        If ReminderTK2 < 0 Then
                            ReminderTK2 = (ReminderTK2 + 65536) Mod 65536
                        End If
                        If ReminderSKY < 0 Then
                            ReminderSKY = (ReminderSKY + 65536) Mod 65536
                        End If

                        encrypteddata = (bitdata - ReminderSKY - ((ReminderPK0 * ReminderTK1) + ReminderTK2)) Mod 65536
                        If encrypteddata < 0 Then
                            encrypteddata += 65536
                        End If

                    Else
                        If bitdata < keycounter Then
                            ReminderPK0 = BigInteger.Remainder(PasswordKeys, keycounter)
                            ReminderTK1 = BigInteger.Remainder(Token1Keys, keycounter)
                            ReminderTK2 = BigInteger.Remainder(Token2Keys, keycounter)
                            ReminderSKY = BigInteger.Remainder(SharedKeys, keycounter)

                            If ReminderPK0 < 0 Then
                                ReminderPK0 = (ReminderPK0 + keycounter) Mod keycounter
                            End If
                            If ReminderTK1 < 0 Then
                                ReminderTK1 = (ReminderTK1 + keycounter) Mod keycounter
                            End If
                            If ReminderTK2 < 0 Then
                                ReminderTK2 = (ReminderTK2 + keycounter) Mod keycounter
                            End If
                            If ReminderSKY < 0 Then
                                ReminderSKY = (ReminderSKY + keycounter) Mod keycounter
                            End If


                            encrypteddata = (bitdata - ReminderSKY - ((ReminderPK0 * ReminderTK1) + ReminderTK2)) Mod keycounter
                            If encrypteddata < 0 Then
                                encrypteddata += keycounter
                            End If
                        Else
                            Return Nothing
                        End If
                    End If
                    qbytes = BitConverter.GetBytes(encrypteddata)
                    destinationdata(bytectr) = qbytes(0)
                    destinationdata(bytectr + 1) = qbytes(1)
                    keycounter += 1
                    If keycounter = 65536 Then
                        keycounter = 32768
                    End If

                    bytectr += 2
                    finalcnt += 2
                End While
                Dim hebytes = ConvertFromQuickHEBytes(destinationdata)
                Dim responsedata = Newtonsoft.Json.JsonConvert.DeserializeObject(System.Text.Encoding.UTF8.GetString(hebytes).Replace(vbNullChar, ""))
                Return responsedata.ToString()
            Catch ex As Exception
                Return Nothing
            End Try
        End Function

        Private Function DecryptV3EncryptedRawMessage(ByVal messagedata As Byte(), ByVal PasswordKeys As BigInteger, ByVal Token1Keys As BigInteger, ByVal Token2Keys As BigInteger, ByVal SharedKeys As BigInteger) As Byte()
            Try
                Dim keycounter As Integer
                keycounter = BitConverter.ToUInt16(messagedata, 0)
                If keycounter > 65536 Then
                    keycounter = (keycounter Mod 32768) + 32768
                End If
                Dim qbytes(1) As Byte
                qbytes = BitConverter.GetBytes(keycounter)
                Dim destinationdata(messagedata.Length - 1) As Byte
                destinationdata(0) = qbytes(0)
                destinationdata(1) = qbytes(1)
                Dim ReminderPK0 As BigInteger
                Dim ReminderTK1 As BigInteger
                Dim ReminderTK2 As BigInteger
                Dim ReminderSKY As BigInteger

                Dim encrypteddata As Integer
                Dim finalcnt As Integer = 0
                Dim bytectr As Int64
                bytectr = 2
                finalcnt = 0
                Dim bitdata As UInt16
                While bytectr < messagedata.Length
                    If finalcnt = 64 Then
                        finalcnt = 0
                    End If
                    bitdata = BitConverter.ToUInt16(messagedata, bytectr)
                    If (finalcnt > 57) Then
                        ReminderPK0 = BigInteger.Remainder(PasswordKeys, 65536)
                        ReminderTK1 = BigInteger.Remainder(Token1Keys, 65536)
                        ReminderTK2 = BigInteger.Remainder(Token2Keys, 65536)
                        ReminderSKY = BigInteger.Remainder(SharedKeys, 65536)
                        If ReminderPK0 < 0 Then
                            ReminderPK0 = (ReminderPK0 + 65536) Mod 65536
                        End If
                        If ReminderTK1 < 0 Then
                            ReminderTK1 = (ReminderTK1 + 65536) Mod 65536
                        End If
                        If ReminderTK2 < 0 Then
                            ReminderTK2 = (ReminderTK2 + 65536) Mod 65536
                        End If
                        If ReminderSKY < 0 Then
                            ReminderSKY = (ReminderSKY + 65536) Mod 65536
                        End If

                        encrypteddata = (bitdata - ReminderSKY - ((ReminderPK0 * ReminderTK1) + ReminderTK2)) Mod 65536
                        If encrypteddata < 0 Then
                            encrypteddata += 65536
                        End If

                    Else
                        If bitdata < keycounter Then
                            ReminderPK0 = BigInteger.Remainder(PasswordKeys, keycounter)
                            ReminderTK1 = BigInteger.Remainder(Token1Keys, keycounter)
                            ReminderTK2 = BigInteger.Remainder(Token2Keys, keycounter)
                            ReminderSKY = BigInteger.Remainder(SharedKeys, keycounter)

                            If ReminderPK0 < 0 Then
                                ReminderPK0 = (ReminderPK0 + keycounter) Mod keycounter
                            End If
                            If ReminderTK1 < 0 Then
                                ReminderTK1 = (ReminderTK1 + keycounter) Mod keycounter
                            End If
                            If ReminderTK2 < 0 Then
                                ReminderTK2 = (ReminderTK2 + keycounter) Mod keycounter
                            End If
                            If ReminderSKY < 0 Then
                                ReminderSKY = (ReminderSKY + keycounter) Mod keycounter
                            End If


                            encrypteddata = (bitdata - ReminderSKY - ((ReminderPK0 * ReminderTK1) + ReminderTK2)) Mod keycounter
                            If encrypteddata < 0 Then
                                encrypteddata += keycounter
                            End If
                        Else
                            Return Nothing
                        End If
                    End If
                    qbytes = BitConverter.GetBytes(encrypteddata)
                    destinationdata(bytectr) = qbytes(0)
                    destinationdata(bytectr + 1) = qbytes(1)
                    keycounter += 1
                    If keycounter = 65536 Then
                        keycounter = 32768
                    End If

                    bytectr += 2
                    finalcnt += 2
                End While
                Return destinationdata
            Catch ex As Exception
                Return New Byte() {}
            End Try
        End Function


        Private Function GenSHA512Byte(ByVal inputString As String) As Byte()
            Try
                Dim sha256 As SHA512 = SHA512Managed.Create()
                Dim bytes As Byte() = Encoding.UTF8.GetBytes(inputString)
                Dim hash As Byte() = sha256.ComputeHash(bytes)
                Dim stringBuilder As New StringBuilder()
                For i As Integer = 0 To hash.Length - 1
                    stringBuilder.Append(hash(i).ToString("X2"))
                Next
                Return hash
            Catch ex As Exception
                Return Nothing
            End Try
        End Function
        Private Function GenerateSHA512Byte(ByVal inputString As String) As Byte()
            Try
                Dim sha256 As SHA512 = SHA512Managed.Create()
                Dim bytes As Byte() = Encoding.UTF8.GetBytes(inputString)
                Dim hash As Byte() = sha256.ComputeHash(bytes)
                Dim stringBuilder As New StringBuilder()
                For i As Integer = 0 To hash.Length - 1
                    stringBuilder.Append(hash(i).ToString("X2"))
                Next
                Return hash
            Catch ex As Exception
                Return Nothing
            End Try
        End Function

        Private Function BuildJsonData(ByVal request As String, ByVal sender As String, ByVal receiver As String, body As String) As String
            Try
                Dim jsonstringreq As New StringBuilder()
                Dim randomcnt As Integer
                randomcnt = New Random().Next(2, 4)
                Dim cnt As Integer = 0
                Dim uTime As Int64
                uTime = (DateTime.UtcNow - New DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds
                Dim jw As New StringWriter(jsonstringreq)
                Using writer As JsonWriter = New JsonTextWriter(jw)
                    writer.WriteStartObject()
                    While cnt < randomcnt
                        writer.WritePropertyName(Guid.NewGuid().ToString().Substring(0, 2))
                        writer.WriteValue(Guid.NewGuid().ToString().Substring(0, 2))
                        cnt += 1
                    End While
                    writer.WritePropertyName("REQUEST")
                    writer.WriteValue(request)
                    writer.WritePropertyName("SENDER")
                    writer.WriteValue(sender)
                    writer.WritePropertyName("RECEIVER")
                    writer.WriteValue(receiver)
                    writer.WritePropertyName("CURRENTTIME")
                    writer.WriteValue(uTime.ToString())
                    writer.WritePropertyName("BODY")
                    writer.WriteValue(body)
                    cnt = 0
                    randomcnt = New Random().Next(2, 4)
                    While cnt < randomcnt
                        writer.WritePropertyName(Guid.NewGuid().ToString().Substring(0, 2))
                        writer.WriteValue(Guid.NewGuid().ToString().Substring(0, 2))
                        cnt += 1
                    End While
                    writer.WriteEndObject()
                End Using
                Return jsonstringreq.ToString() + "  "
            Catch ex As Exception
                Return ""
            End Try
        End Function

        Private Function BuildUserJsonData(ByVal request As String, ByVal sender As String, ByVal receiver As String, body As String, messagesenttime As String) As String
            Try
                Dim jsonstringreq As New StringBuilder()
                Dim randomcnt As Integer
                randomcnt = New Random().Next(2, 4)
                Dim cnt As Integer = 0
                Dim uTime As Int64
                uTime = (DateTime.UtcNow - New DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds
                Dim jw As New StringWriter(jsonstringreq)
                Using writer As JsonWriter = New JsonTextWriter(jw)
                    writer.WriteStartObject()
                    writer.WritePropertyName("REQUEST")
                    writer.WriteValue(request)
                    writer.WritePropertyName("SENDER")
                    writer.WriteValue(sender)
                    writer.WritePropertyName("RECEIVER")
                    writer.WriteValue(receiver)
                    writer.WritePropertyName("STIME")
                    writer.WriteValue(messagesenttime)
                    writer.WritePropertyName("RTIME")
                    writer.WriteValue(uTime.ToString)
                    writer.WritePropertyName("BODY")
                    writer.WriteValue(body)
                    writer.WriteEndObject()
                End Using
                Return jsonstringreq.ToString()
            Catch ex As Exception
                Return ""
            End Try
        End Function



        Public Sub New(ByVal ILoginToken As String, ByVal IResource As String, ByVal ISecret As String)
            LoginToken = ILoginToken
            Resource = IResource
            TokenSecret = Convert.ToBase64String(GenSHA512Byte(ISecret))
            Hexa8RAhost = "hexaeight-sso-platform.p.rapidapi.com"
        End Sub

        Public Sub SetRapidAPIKey(ByVal APIKey As String)
            RapidAPIKey = APIKey
            Get_sharedkey_usingtoken_url = "https://" + Hexa8RAhost + "/get-sharedkey-usingtoken?rapidapi-key=" + RapidAPIKey
            Get_sharedkey_usingname_url = "https://" + Hexa8RAhost + "/get-sharedkey-usingname?rapidapi-key=" + RapidAPIKey
            Get_presharedkey_usingname_url = "https://" + Hexa8RAhost + "/get-presharedkey-usingname?rapidapi-key=" + RapidAPIKey
            Get_clientappsharedkey_usingname_url = "https://" + Hexa8RAhost + "/fetch-dest-clientsk?rapidapi-key=" + RapidAPIKey

        End Sub
        Public Sub SetDataLocation(ByVal Location As String)
            DBLocation = "Filename='" + DBLocation + "HESession.db';connection=shared"
            'DBLocation = Location.ToString().Trim()
        End Sub

        Private Function ExpandString(ByVal str As String, ByVal length As Integer) As String
            If length <= str.Length Then Return str.Substring(0, length)
            While str.Length * 2 <= length
                str += str
            End While
            If str.Length < length Then
                str += str.Substring(0, length - str.Length)
            End If
            Return str
        End Function

        Public Sub SetSafeKey(ByVal Xsafekey As String)
            SafeKey = ExpandString(Xsafekey, 32)
        End Sub


        Public Function GetSharedKeyByKnownName(ByVal Recipient As String) As String
            Dim Preauthkeys = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-preauth-keys", "", "")
            If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then
                Dim HexaEightSharedKeys = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-sharedkey-for-hexaeight", "", "")
                If HexaEightSharedKeys <> "" AndAlso HexaEightSharedKeys IsNot Nothing Then
                    Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                    Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                    Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                    Dim jsonstringreq = ""
                    If Resource <> "" Then
                        jsonstringreq = BuildJsonData("NEWENCRYPTIONKEY", Resource, Recipient, "Requesting Shared Keys")
                        Dim hebytes = Convert2QuickHEBytes(jsonstringreq)
                        If hebytes.Count > 0 Then
                            Dim htmlbody = Convert.ToBase64String(CreateV3EncryptedRequestForDestination(hebytes, GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(HexaEightSharedKeys))))
                            'Dim serverresponse = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-sharedkey-usingname", htmlbody, "")
                            Dim serverresponse = PerformHttpWebRequest(LoginToken, Get_sharedkey_usingname_url, htmlbody, "")
                            Dim newresourceresponse As String = ""
                            If serverresponse.StartsWith("HEEnc:") Then
                                newresourceresponse = DecryptV3EncryptedRequestFromDestination(Convert.FromBase64String(serverresponse.Split(":")(1)), GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(HexaEightSharedKeys)))
                                Try
                                    Dim responsetemplate = New With {Key .REQUEST = "", .SENDER = "", .RECEIVER = "", .BODY = ""}
                                    Dim responsedata = JsonConvert.DeserializeAnonymousType(newresourceresponse, responsetemplate)
                                    If responsedata.BODY.ToString().StartsWith("ReceiverSharedKeys") Then
                                        Dim RecipientSharedKeys = responsedata.BODY.ToString().Split("|")(1)
                                        Return Preauthkeys + ":" + RecipientSharedKeys
                                    Else
                                        Return ""
                                    End If
                                Catch ex As Exception
                                    Return ""
                                End Try
                            Else
                                Return ""
                            End If
                        Else
                            Return ""
                        End If
                    Else
                        Return ""
                    End If
                Else
                    Return ""
                End If
            Else
                Return ""
            End If
        End Function

        Public Function GetSharedKeyForClientApp(ByVal token As String) As String
            Return PerformHttpWebRequest(LoginToken, Get_clientappsharedkey_usingname_url, token, "")
        End Function

        Public Function GetPreSharedKeyByKnownName(ByVal Recipient As String, ByVal UnixTimeStamp As String) As String
            If ((DateTime.UtcNow - New DateTime(1970, 1, 1, 0, 0, 0)).TotalMinutes - CInt(UnixTimeStamp)) > 60 Then
                Return "-4"
            End If
            Dim Preauthkeys = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-preauth-keys", "", "")
            If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then
                Dim HexaEightSharedKeys = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-sharedkey-for-hexaeight", "", "")
                If HexaEightSharedKeys <> "" AndAlso HexaEightSharedKeys IsNot Nothing Then
                    Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                    Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                    Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                    Dim jsonstringreq = ""
                    If Resource <> "" Then
                        jsonstringreq = BuildJsonData("NEWENCRYPTIONKEY", Resource, Recipient, UnixTimeStamp)
                        Dim hebytes = Convert2QuickHEBytes(jsonstringreq)
                        If hebytes.Count > 0 Then
                            Dim htmlbody = Convert.ToBase64String(CreateV3EncryptedRequestForDestination(hebytes, GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(HexaEightSharedKeys))))
                            'Dim serverresponse = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-presharedkey-usingname", htmlbody, "")
                            Dim serverresponse = PerformHttpWebRequest(LoginToken, Get_presharedkey_usingname_url, htmlbody, "")
                            Dim newresourceresponse As String = ""
                            If serverresponse.StartsWith("HEEnc:") Then
                                newresourceresponse = DecryptV3EncryptedRequestFromDestination(Convert.FromBase64String(serverresponse.Split(":")(1)), GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(HexaEightSharedKeys)))
                                Try
                                    Dim responsetemplate = New With {Key .REQUEST = "", .SENDER = "", .RECEIVER = "", .BODY = ""}
                                    Dim responsedata = JsonConvert.DeserializeAnonymousType(newresourceresponse, responsetemplate)
                                    If responsedata.BODY.ToString().StartsWith("ReceiverSharedKeys") Then
                                        Dim RecipientSharedKeys = responsedata.BODY.ToString().Split("|")(1)
                                        Return RecipientSharedKeys
                                    Else
                                        Return ""
                                    End If
                                Catch ex As Exception
                                    Return ""
                                End Try
                            Else
                                Return ""
                            End If
                        Else
                            Return ""
                        End If
                    Else
                        Return ""
                    End If
                Else
                    Return ""
                End If
            Else
                Return ""
            End If
        End Function






        Public Function EncryptMessageByKnownName(ByVal Recipient As String, ByVal Message As String) As String
            Dim Preauthkeys = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-preauth-keys", "", "")
            If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then
                Dim HexaEightSharedKeys = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-sharedkey-for-hexaeight", "", "")
                If HexaEightSharedKeys <> "" AndAlso HexaEightSharedKeys IsNot Nothing Then
                    Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                    Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                    Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                    Dim jsonstringreq = ""
                    If Resource <> "" Then
                        jsonstringreq = BuildJsonData("NEWENCRYPTIONKEY", Resource, Recipient, "Requesting Shared Keys")
                        Dim hebytes = Convert2QuickHEBytes(jsonstringreq)
                        If hebytes.Count > 0 Then
                            Dim htmlbody = Convert.ToBase64String(CreateV3EncryptedRequestForDestination(hebytes, GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(HexaEightSharedKeys))))
                            'Dim serverresponse = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-sharedkey-usingname", htmlbody, "")
                            Dim serverresponse = PerformHttpWebRequest(LoginToken, Get_sharedkey_usingname_url, htmlbody, "")
                            Dim newresourceresponse As String = ""
                            If serverresponse.StartsWith("HEEnc:") Then
                                newresourceresponse = DecryptV3EncryptedRequestFromDestination(Convert.FromBase64String(serverresponse.Split(":")(1)), GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(HexaEightSharedKeys)))
                                Try
                                    Dim responsetemplate = New With {Key .REQUEST = "", .SENDER = "", .RECEIVER = "", .BODY = ""}
                                    Dim responsedata = JsonConvert.DeserializeAnonymousType(newresourceresponse, responsetemplate)
                                    If responsedata.BODY.ToString().StartsWith("ReceiverSharedKeys") Then
                                        Dim RecipientSharedKeys = responsedata.BODY.ToString().Split("|")(1)
                                        Dim jsonmessagereq As String = ""
                                        jsonmessagereq = BuildJsonData("DATAMESSAGE", Resource, Recipient, Message)
                                        Dim msgbytes As Byte() = Convert2QuickHEBytes(jsonmessagereq)
                                        Dim messagebody = Convert.ToBase64String(CreateV3EncryptedRequestForDestination(msgbytes, GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(RecipientSharedKeys))))
                                        Return messagebody
                                    Else
                                        Return ""
                                    End If
                                Catch ex As Exception
                                    Return ""
                                End Try
                            Else
                                Return ""
                            End If
                        Else
                            Return ""
                        End If
                    Else
                        Return ""
                    End If
                Else
                    Return ""
                End If
            Else
                Return ""
            End If
        End Function

        Public Function EncryptMessageUsingUAK(ByVal Recipient As String, ByVal Message As String, ByVal UAK As String, ByVal AsymetricSharedkey As String) As String
            Try
                Dim Preauthkeys = AsymetricSharedkey.Split(":")(0) + ":" + AsymetricSharedkey.Split(":")(1)
                If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then

                    Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                    Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                    Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                    Dim jsonmessagereq As String = ""
                    jsonmessagereq = BuildJsonData("DATAMESSAGE", Resource, Recipient, Message)
                    Dim msgbytes As Byte() = Convert2QuickHEBytes(jsonmessagereq)
                    Dim messagebody = Convert.ToBase64String(CreateV3EncryptedRequestForUser(msgbytes, GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(UAK)), New BigInteger(Convert.FromBase64String(AsymetricSharedkey.Split(":")(2)))))
                    Return messagebody
                Else
                    Return ""
                End If
            Catch ex As Exception
                Return ""
            End Try
        End Function

        Public Function EncryptUserMessageUsingUAK(ByVal Source As String, ByVal Recipient As String, ByVal Message As String, ByVal UAK As String, ByVal AsymetricSharedkey As String) As String
            Try
                Dim Preauthkeys = AsymetricSharedkey.Split(":")(0) + ":" + AsymetricSharedkey.Split(":")(1)
                If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then

                    Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                    Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                    Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                    Dim jsonmessagereq As String = ""
                    jsonmessagereq = BuildJsonData("DATAMESSAGE", Source, Recipient, Message)
                    Dim msgbytes As Byte() = Convert2QuickHEBytes(jsonmessagereq)
                    Dim messagebody = Convert.ToBase64String(CreateV3EncryptedRequestForUser(msgbytes, GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(UAK)), New BigInteger(Convert.FromBase64String(AsymetricSharedkey.Split(":")(2)))))
                    Return messagebody
                Else
                    Return ""
                End If
            Catch ex As Exception
                Return ""
            End Try
        End Function


        Public Function DecryptUserMessageUsingUAK(ByVal EncryptedMessage As String, ByVal UAK As String, ByVal AsymetricSharedkey As String) As String
            Dim Preauthkeys = AsymetricSharedkey.Split(":")(0) + ":" + AsymetricSharedkey.Split(":")(1)
            If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then
                Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                Dim DecryptedMessage = DecryptV3EncryptedRequestUsingUAK(Convert.FromBase64String(EncryptedMessage), GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(UAK)), New BigInteger(Convert.FromBase64String(AsymetricSharedkey.Split(":")(2))))
                Try
                    Dim resptemplate = New With {Key .REQUEST = "", .SENDER = "", .RECEIVER = "", .CURRENTTIME = "", .BODY = ""}
                    Dim datamessage = JsonConvert.DeserializeAnonymousType(DecryptedMessage, resptemplate)
                    Return BuildUserJsonData(datamessage.REQUEST.ToString(), datamessage.SENDER.ToString(), datamessage.RECEIVER.ToString(), datamessage.BODY.ToString(), datamessage.CURRENTTIME.ToString())
                Catch ex As Exception
                    Return ""
                End Try
            Else
                Return ""
            End If
        End Function


        Public Function DecryptMessageForUAK(ByVal EncryptedMessage As String, ByVal AsymetricSharedkey As String) As String
            Dim Preauthkeys = AsymetricSharedkey.Split(":")(0) + ":" + AsymetricSharedkey.Split(":")(1)
            If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then
                Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                Dim DecryptedMessage = DecryptV3EncryptedRequestFromUser(Convert.FromBase64String(EncryptedMessage), GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(AsymetricSharedkey.Split(":")(2))))
                Try
                    Dim resptemplate = New With {Key .REQUEST = "", .SENDER = "", .RECEIVER = "", .CURRENTTIME = "", .BODY = ""}
                    Dim datamessage = JsonConvert.DeserializeAnonymousType(DecryptedMessage, resptemplate)
                    Return BuildUserJsonData(datamessage.REQUEST.ToString(), datamessage.SENDER.ToString(), datamessage.RECEIVER.ToString(), datamessage.BODY.ToString(), datamessage.CURRENTTIME.ToString())
                Catch ex As Exception
                    Return ""
                End Try
            Else
                Return ""
            End If
        End Function


        Public Function EncryptMessageUsingSharedKey(ByVal Recipient As String, ByVal Message As String, ByVal AsymetricSharedkey As String) As String
            Try
                Dim Preauthkeys = AsymetricSharedkey.Split(":")(0) + ":" + AsymetricSharedkey.Split(":")(1)
                If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then

                    Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                    Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                    Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                    Dim jsonmessagereq As String = ""
                    jsonmessagereq = BuildJsonData("DATAMESSAGE", Resource, Recipient, Message)
                    Dim msgbytes As Byte() = Convert2QuickHEBytes(jsonmessagereq)
                    Dim messagebody = Convert.ToBase64String(CreateV3EncryptedRequestForDestination(msgbytes, GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(AsymetricSharedkey.Split(":")(2)))))
                    Return messagebody
                Else
                    Return ""
                End If
            Catch ex As Exception
                Return ""
            End Try
        End Function



        Public Function DecryptMessageUsingSharedKey(ByVal EncryptedMessage As String, ByVal AsymetricSharedkey As String) As String
            Dim Preauthkeys = AsymetricSharedkey.Split(":")(0) + ":" + AsymetricSharedkey.Split(":")(1)
            If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then
                Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                Dim DecryptedMessage = DecryptV3EncryptedRequestFromDestination(Convert.FromBase64String(EncryptedMessage), GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(AsymetricSharedkey.Split(":")(2))))
                Try
                    Dim resptemplate = New With {Key .REQUEST = "", .SENDER = "", .RECEIVER = "", .CURRENTTIME = "", .BODY = ""}
                    Dim datamessage = JsonConvert.DeserializeAnonymousType(DecryptedMessage, resptemplate)
                    Return BuildUserJsonData(datamessage.REQUEST.ToString(), datamessage.SENDER.ToString(), datamessage.RECEIVER.ToString(), datamessage.BODY.ToString(), datamessage.CURRENTTIME.ToString())
                Catch ex As Exception
                    Return ""
                End Try
            Else
                Return ""
            End If
        End Function


        Public Function DecryptMessageByKnownName(ByVal Recipient As String, ByVal EncryptedMessage As String) As String
            Dim Preauthkeys = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-preauth-keys", "", "")
            If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then
                Dim HexaEightSharedKeys = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-sharedkey-for-hexaeight", "", "")
                If HexaEightSharedKeys <> "" AndAlso HexaEightSharedKeys IsNot Nothing Then
                    Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                    Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                    Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                    Dim jsonstringreq = ""
                    If Resource <> "" Then
                        jsonstringreq = BuildJsonData("NEWENCRYPTIONKEY", Resource, Recipient, "Requesting Shared Keys")
                        Dim hebytes = Convert2QuickHEBytes(jsonstringreq)
                        If hebytes.Count > 0 Then
                            Dim htmlbody = Convert.ToBase64String(CreateV3EncryptedRequestForDestination(hebytes, GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(HexaEightSharedKeys))))
                            'Dim serverresponse = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-sharedkey-usingname", htmlbody, "")
                            Dim serverresponse = PerformHttpWebRequest(LoginToken, Get_sharedkey_usingname_url, htmlbody, "")
                            Dim newresourceresponse As String = ""
                            If serverresponse.StartsWith("HEEnc:") Then
                                newresourceresponse = DecryptV3EncryptedRequestFromDestination(Convert.FromBase64String(serverresponse.Split(":")(1)), GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(HexaEightSharedKeys)))
                                Try
                                    Dim responsetemplate = New With {Key .REQUEST = "", .SENDER = "", .RECEIVER = "", .BODY = ""}
                                    Dim responsedata = JsonConvert.DeserializeAnonymousType(newresourceresponse, responsetemplate)
                                    If responsedata.BODY.ToString().StartsWith("ReceiverSharedKeys") Then
                                        Dim RecipientSharedKeys = responsedata.BODY.ToString().Split("|")(1)

                                        Dim DecryptedMessage = DecryptV3EncryptedRequestFromDestination(Convert.FromBase64String(EncryptedMessage), GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(RecipientSharedKeys)))
                                        Try
                                            Dim resptemplate = New With {Key .REQUEST = "", .SENDER = "", .RECEIVER = "", .CURRENTTIME = "", .BODY = ""}
                                            Dim datamessage = JsonConvert.DeserializeAnonymousType(DecryptedMessage, resptemplate)
                                            If datamessage.SENDER.ToString() = Recipient And datamessage.RECEIVER.ToString() = Resource Then
                                                Return BuildUserJsonData(datamessage.REQUEST.ToString(), datamessage.SENDER.ToString(), datamessage.RECEIVER.ToString(), datamessage.BODY.ToString(), datamessage.CURRENTTIME.ToString())
                                            Else
                                                Return ""
                                            End If
                                        Catch ex As Exception
                                            Return ""
                                        End Try
                                    Else
                                        Return ""
                                    End If
                                Catch ex As Exception
                                    Return ""
                                End Try
                            Else
                                Return ""
                            End If
                        Else
                            Return ""
                        End If
                    Else
                        Return ""
                    End If
                Else
                    Return ""
                End If
            Else
                Return ""
            End If
        End Function

        Public Function DecryptMessageUsingHEToken(ByVal EncryptedMessage As String) As String
            Dim encryptedtoken As String = ""
            Dim encrypteddata As String = ""
            Try
                encryptedtoken = EncryptedMessage.Split(".")(0)
                encrypteddata = EncryptedMessage.Split(".")(1)
            Catch ex As Exception
                Return ""
            End Try
            Dim Preauthkeys = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-preauth-keys", "", "")
            If Preauthkeys <> "" AndAlso Preauthkeys IsNot Nothing Then
                Dim HexaEightSharedKeys = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-sharedkey-for-hexaeight", "", "")
                If HexaEightSharedKeys <> "" AndAlso HexaEightSharedKeys IsNot Nothing Then
                    Dim GeneratedToken1 As BigInteger = New BigInteger(GenerateSHA512Byte(Resource))
                    Dim GeneratedToken2 As BigInteger = New BigInteger(Convert.FromBase64String(TokenSecret))
                    Dim GeneratedToken = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)
                    Dim jsonstringreq = ""
                    If Resource <> "" Then
                        jsonstringreq = BuildJsonData("NEWENCRYPTIONKEY", Resource, encryptedtoken, "Requesting Shared Keys")
                        Dim hebytes = Convert2QuickHEBytes(jsonstringreq)
                        If hebytes.Count > 0 Then
                            Dim htmlbody = Convert.ToBase64String(CreateV3EncryptedRequestForDestination(hebytes, GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(HexaEightSharedKeys))))
                            'Dim serverresponse = PerformHttpWebRequest(LoginToken, "https://hexaeight.com/get-sharedkey-usingtoken", htmlbody, "")
                            Dim serverresponse = PerformHttpWebRequest(LoginToken, Get_sharedkey_usingtoken_url, htmlbody, "")
                            Dim newresourceresponse As String = ""
                            If serverresponse.StartsWith("HEEnc:") Then
                                newresourceresponse = DecryptV3EncryptedRequestFromDestination(Convert.FromBase64String(serverresponse.Split(":")(1)), GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(HexaEightSharedKeys)))
                                Try
                                    Dim responsetemplate = New With {Key .REQUEST = "", .SENDER = "", .RECEIVER = "", .BODY = ""}
                                    Dim responsedata = JsonConvert.DeserializeAnonymousType(newresourceresponse, responsetemplate)
                                    If responsedata.BODY.ToString().StartsWith("ReceiverSharedKeys") Then
                                        Dim RecipientSharedKeys = responsedata.BODY.ToString().Split("|")(1)
                                        Dim Recipient = responsedata.BODY.ToString().Split("|")(2)

                                        Dim DecryptedMessage = DecryptV3EncryptedRequestFromDestination(Convert.FromBase64String(encrypteddata), GeneratedToken, New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(0)))), New BigInteger(Convert.FromBase64String((Preauthkeys.Split(":")(1)))), New BigInteger(Convert.FromBase64String(RecipientSharedKeys)))
                                        Try
                                            Dim resptemplate = New With {Key .REQUEST = "", .SENDER = "", .RECEIVER = "", .CURRENTTIME = "", .BODY = ""}
                                            Dim datamessage = JsonConvert.DeserializeAnonymousType(DecryptedMessage, resptemplate)
                                            If datamessage.SENDER.ToString() = Recipient And datamessage.RECEIVER.ToString() = Resource Then
                                                Return BuildUserJsonData(datamessage.REQUEST.ToString(), datamessage.SENDER.ToString(), datamessage.RECEIVER.ToString(), datamessage.BODY.ToString(), datamessage.CURRENTTIME.ToString())
                                            Else
                                                Return ""
                                            End If
                                        Catch ex As Exception
                                            Return ""
                                        End Try
                                    Else
                                        Return ""
                                    End If
                                Catch ex As Exception
                                    Return ""
                                End Try
                            Else
                                Return ""
                            End If
                        Else
                            Return ""
                        End If
                    Else
                        Return ""
                    End If
                Else
                    Return ""
                End If
            Else
                Return ""
            End If
        End Function



End Namespace
