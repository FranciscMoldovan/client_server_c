#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "..\utils\utils.h"
#include "commands.h"
#include "data.h"
#include "server.h"
#include "crypto.h"

#include <time.h>
#define DEFAULT_PORT    "27015"

extern progress;

char recvbuf[DEFAULT_BUFLEN];
char sendbuf[DEFAULT_BUFLEN];

static char* last_created_file_name=NULL;
static size_t last_created_file_name_size;
static char* logged_in_user_name = NULL;
static size_t logged_in_user_name_size;

typedef enum {
    CONN_INVALID = 0,
    CONN_UNAUTHENTICATED,       // Can change to: CONN_USER_OK (if 'user XXX' matches a correct user)
    CONN_USER_OK,               // Can change to: UNAUTHENTICATED (if 'pass XXX' fails too many times), or AUTHENTICATED (if 'pass XXX' matches correct password) 
    CONN_AUTHENTICATED,         // Can change to: UNAUTHENTICATED (if 'logoff' is given)
} CONNECTION_STATE;


#define CMD_EXIT        "exit"
#define CMD_USER        "user"
#define CMD_PASS        "pass"
#define CMD_LOGOFF      "logoff"
#define CMD_LIST        "list"
#define CMD_GET         "get"
#define CMD_AVAIL       "avail"
#define CMD_INFO        "info"

#define CMD_NEWFILE		"newfile"
#define CMD_WRITEFILE	"writefile"
#define CMD_ENCRYPTFILE	"encryptfile"

void SetReply(
    char *Output,
    int *OutLength,
    char *Message
    )
{
    sprintf_s(Output, DEFAULT_BUFLEN, Message);
    printf("Returning: %s\n", Output);
    *OutLength = strlen(Output);
}

void
Log(
    const char *Format,
    ...
    )
{
    char dest[1024];
    va_list argptr;
    FILE *file;

    va_start(argptr, Format);
   // vsprintf_s(dest, 128, Format, argptr);
	vsprintf_s(dest, 1024, Format, argptr);
    va_end(argptr);
    
    fopen_s(&file, "log.txt", "a");
    if (NULL != file)
    {
        fprintf(file, dest);
        fclose(file);
    }
    else
    {
        printf("Error opening log.txt file!\n");
    }
}


//
// Returns TRUE if we should continue processing otherwise, and FALSE otherwise (when 'exit' has been given).
//
BOOLEAN InterpretCommand(
    char *Command,
    char *Parameter,
    char *Output,
    int *OutLength,
    CONNECTION_STATE *State,
    int *UserId
    )
{
    UNREFERENCED_PARAMETER(UserId);
    UNREFERENCED_PARAMETER(Parameter);

    printf("[DEBUG] State = %d, Command = [%s], Parameter = [%s], UserId = %d\n", *State, Command, Parameter, *UserId);

    if (*State == CONN_UNAUTHENTICATED)
    {
		// Command = 'NEWFILE'
		if (0 == _stricmp(Command, CMD_NEWFILE) ||
			0 == _stricmp(Command, CMD_WRITEFILE) ||
			0 == _stricmp(Command, CMD_ENCRYPTFILE))
		{
			SetReply(Output, OutLength, "[ERROR] Please Log In for file manipulation!");
			return TRUE;
		}

        // Command = 'EXIT', Parameter = NULL
        if (0 == _stricmp(Command, CMD_EXIT))
        {
            *State = CONN_INVALID;
            SetReply(Output, OutLength, "[OK] Exiting.");
            return FALSE;
        }

        // Command = 'USER', Parameter = username
        if (0 == _stricmp(Command, CMD_USER))
        {
            if (NULL == Parameter)
            {
                SetReply(Output, OutLength, "[ERROR] No username provided.");
                return TRUE;
            }

            if (CmdHandleUser(Parameter, UserId))
            {
                *State = CONN_USER_OK;
                SetReply(Output, OutLength, "[OK] User is valid, provide password.");
                return TRUE;
            }

            SetReply(Output, OutLength, "[ERROR] Invalid user, try again.");
            return TRUE;
        }
    }

    if (*State == CONN_USER_OK)
    {
        // Command = 'EXIT', Parameter = NULL
        if (0 == _stricmp(Command, CMD_EXIT))
        {
            *State = CONN_INVALID;
            SetReply(Output, OutLength, "[OK] Exiting.");
            return FALSE;
        }

        // Command = 'USER', Parameter = username
        if (0 == _stricmp(Command, CMD_USER))
        {
            if (NULL == Parameter)
            {
                SetReply(Output, OutLength, "[ERROR] No username provided.");
                return TRUE;
            }

            if (CmdHandleUser(Parameter, UserId))
            {
                *State = CONN_USER_OK;
                SetReply(Output, OutLength, "[OK] User is valid, provide password.");
                return TRUE;
            }

            *State = CONN_UNAUTHENTICATED;
            *UserId = -1;
            SetReply(Output, OutLength, "[ERROR] Invalid user, try again.");
            return TRUE;
        }

        // Command = 'PASS', Parameter = password
        if (0 == _stricmp(Command, CMD_PASS))
        {
            if (NULL == Parameter)
            {
                SetReply(Output, OutLength, "[ERROR] No password provided.");
                return TRUE;
            }

            if (CmdHandlePass(*UserId, Parameter))
            {
                *State = CONN_AUTHENTICATED;
                SetReply(Output, OutLength, "[OK] Authentication successful.");

                Log("[LOGIN] User %s (%d) logged in\n", gUserData[*UserId].Username, *UserId);
				///
				logged_in_user_name_size = strlen(gUserData[*UserId].Username);
				logged_in_user_name = (char*)malloc((2+logged_in_user_name_size)*sizeof(char));
				memcpy(logged_in_user_name, &(gUserData[*UserId].Username), logged_in_user_name_size);
				logged_in_user_name[logged_in_user_name_size] = '\\';
				logged_in_user_name[logged_in_user_name_size+1] = '\0';

				printf("YOU ARE LOGGED AS %s", logged_in_user_name);
				///
                return TRUE;
            }

            Log("[AUTH] User %s (%d) failed to log in with password %s\n", gUserData[*UserId].Username, *UserId, Parameter);

            SetReply(Output, OutLength, "[ERROR] Wrong password.");
            return TRUE;
        }
    }

    if (*State == CONN_AUTHENTICATED)
    {
		
		///////////////// TODO: ADDED
		// Command = 'NEWFILE'
		if (0 == _stricmp(Command, CMD_NEWFILE))
		{
			char *newpath;

			if (NULL == Parameter)
			{
				SetReply(Output, OutLength, "[ERROR] No file provided.");
				return TRUE;
			}

			// Check pattern *.txt
			size_t len = strlen(Parameter);
			if (len > 4 && strcmp(Parameter + len - 4, ".txt") == 0)
			{
				SetReply(Output, OutLength, "FILE OK!");
				
				// Search that file actually exists
				WIN32_FIND_DATA FindFileData;
				HANDLE hFind = INVALID_HANDLE_VALUE;
				//
				// The extra one comes from path \ 
				newpath = (char*)malloc(1 + len + logged_in_user_name_size); 
				memcpy(newpath, logged_in_user_name, 1 + logged_in_user_name_size);
				*(newpath + logged_in_user_name_size) = '\\';
				memcpy(newpath + logged_in_user_name_size + 1, Parameter, strlen(Parameter));
				newpath[1 + len + logged_in_user_name_size] = '\0';
				printf("The PATH=%s\n", newpath); 

				last_created_file_name = newpath;
				//newpath = strcat()
				//
				hFind = FindFirstFile(newpath, &FindFileData);
				GetLastError();

				// Not found
				if (hFind == INVALID_HANDLE_VALUE)
				{
					HANDLE hFile;

					hFile = CreateFile(newpath,
						GENERIC_ALL,
						0,
						NULL,
						CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL,
						NULL);
					if (hFile != INVALID_HANDLE_VALUE)
					{
						SetReply(Output, OutLength, "[OK] Created new file");

//						last_created_file_name_size = strlen(newpath);
//						last_created_file_name = (char*)malloc(last_created_file_name_size);
//						memcpy(last_created_file_name, newpath, last_created_file_name_size);
//						last_created_file_name[last_created_file_name_size] = '\0';

		//				printf("\n\nSTRING LAST FILE MADE = %s\n\n", last_created_file_name);
						CloseHandle(hFile);
					}
					else
					{
						SetReply(Output, OutLength, "[ERROR] File creation error!");
					}
				}
				else
				{
					SetReply(Output, OutLength, "[ERROR] File already exists!");
				}

				CloseHandle(hFind);
				return TRUE;


				//
				newpath = NULL;
				free(newpath);
				//
			}
			else
			{
				SetReply(Output, OutLength, "[ERROR]....FILE format not OK");
				return TRUE;
			}
		
		}

		if (0 == _stricmp(Command, CMD_WRITEFILE))
		{

			// No file created since program startup
			if (NULL == last_created_file_name)
			{
				SetReply(Output, OutLength, "[ERROR] NO HISTORY OF LAST CREATED FILE..");
				return TRUE;
			}
			else
			{ // Try finding it

				WIN32_FIND_DATA FindFileData;
				HANDLE hFind = INVALID_HANDLE_VALUE;

				hFind = FindFirstFile(last_created_file_name, &FindFileData);
				GetLastError();

				// Found
				if (hFind != INVALID_HANDLE_VALUE)
				{
					HANDLE hFile;

					hFile = CreateFile(last_created_file_name,
						FILE_GENERIC_WRITE,
						0,
						NULL,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL,
						NULL);
					// Found the last created. Might have been deleted 
					if (hFile != INVALID_HANDLE_VALUE)
					{
						DWORD dwWritten;

						char* param_with_CRLF;
						param_with_CRLF = (char*)malloc(strlen(Parameter) + 1);
						memcpy(param_with_CRLF, Parameter, strlen(Parameter));
						param_with_CRLF[strlen(Parameter)] = '\n';

						SetFilePointer(hFile, 0, NULL, FILE_END);
						WriteFile(
							hFile,
							param_with_CRLF,
							1 + strlen(Parameter),
							&dwWritten,
							0);

						SetReply(Output, OutLength, "[OK] Written to last created file!");
						CloseHandle(hFile);
						
						// delete allocated PTR
						free(param_with_CRLF);

						return TRUE;
					}

				}


				// SetReply(Output, OutLength, "[OK] Written to last created file!");
				// return TRUE;
			}
		}


		if (0 == _stricmp(Command, CMD_ENCRYPTFILE))
		{

			char *newpath;

			if (NULL == Parameter)
			{
				SetReply(Output, OutLength, "[ERROR] No file provided.");
				return TRUE;
			}

			// Check pattern *.txt
			size_t len = strlen(Parameter);
			if (len > 4 && strcmp(Parameter + len - 4, ".txt") == 0)
			{
				SetReply(Output, OutLength, "[OK]FILE OK!");
				Parameter[strlen(Parameter)] = '\0';

				// The extra one comes from path \ 
				newpath = (char*)malloc(1 + len + logged_in_user_name_size);
				memcpy(newpath, logged_in_user_name, 1 + logged_in_user_name_size);
				*(newpath + logged_in_user_name_size) = '\\';
				memcpy(newpath + logged_in_user_name_size + 1, Parameter, strlen(Parameter));
				newpath[1 + len + logged_in_user_name_size] = '\0';
				printf("The PATH=%s\n", newpath);

				last_created_file_name = newpath;
				//newpath = strcat()


				////////////////////
				// Search that file actually exists
				WIN32_FIND_DATA FindFileData;
				HANDLE hFind = INVALID_HANDLE_VALUE;

				hFind = FindFirstFile(newpath, &FindFileData);
				/////////////////////
				if (INVALID_HANDLE_VALUE != hFind)
				{					
					progress = 0;
					do_work(newpath, 4, 0xAA);
				}

			}
			else
			{
				SetReply(Output, OutLength, "[Error]WRONG FILE FORMAT!");
			}
			return TRUE;
		}
		///////////////// TODO: ADDED




        // Command = 'LOGOFF', Parameter = NULL
        if (0 == _stricmp(Command, CMD_LOGOFF))
        {
            *State = CONN_UNAUTHENTICATED;
            SetReply(Output, OutLength, "[OK] Logged off.");
			//
			last_created_file_name = NULL;
			//
            Log("[LOGOFF] User %s (%d) logged off\n", gUserData[*UserId].Username, *UserId);

            *UserId = -1;

            return TRUE;
        }

        // Command = 'INFO', Parameter = NULL
        if (0 == _stricmp(Command, CMD_INFO))
        {
            // *State doesn't change

            *OutLength = 0;
            Output[0] = 0;

            if (NULL == Parameter)
            {
                SetReply(Output, OutLength, "[ERROR] No parameter given for 'info' command.");
                return TRUE;
            }

            if (!CmdHandleInfo(*UserId, Parameter, Output, OutLength))
            {
                SetReply(Output, OutLength, "[ERROR] Invalid parameter given for 'info' command.");
                return TRUE;
            }
            else
            {
                // Reply has been already set
            }

            return TRUE;
        }

        // Command = 'LIST', Parameter = NULL
        if (0 == _stricmp(Command, CMD_LIST))
        {
            // *State doesn't change

            *OutLength = 0;
            Output[0] = 0;

            SetReply(Output, OutLength, "[OK] Available messages: ");
            
            CmdHandleList(*UserId, Output, OutLength);

            return TRUE;
        }

        // Command = 'GET', Parameter = index
        if (0 == _stricmp(Command, CMD_GET))
        {
            // *State doesn't change

            if (NULL == Parameter)
            {
                SetReply(Output, OutLength, "[ERROR] No message index provided.");
                return TRUE;
            }

            CmdHandleGet(*UserId, Parameter, Output, OutLength);

            return TRUE;
        }
    }

    if (0 == _stricmp(Command, CMD_AVAIL))
    {
        switch(*State)
        {
        case CONN_UNAUTHENTICATED:
            SetReply(Output, OutLength, "[OK] Available commands: exit, user");
            break;
        case CONN_USER_OK:
            SetReply(Output, OutLength, "[OK] Available commands: pass, user, exit");
            break;
        case CONN_AUTHENTICATED:
            SetReply(Output, OutLength, "[OK] Available commands: info, logoff, list, get");
            break;
        }
        return TRUE;
    }

    SetReply(Output, OutLength, "[ERROR] Invalid command.");

    return TRUE;
}


BOOLEAN
ProcessCommand(
    char *Input,
    int InLength,
    char *Output,
    int *OutLength,
    CONNECTION_STATE *State,
    int *UserId
    )
{
    int i = 0;
    int paramIndex = 0;

    PrintBuffer(Input, InLength);

    // Search the end of the command
    while ((Input[i] != ' ') && (i < InLength)) {i++;};

    // Check if we are at the end of the received buffer
    if (i == InLength)
    {
        // Comanda fara parametri
        Input[i] = 0;
        return InterpretCommand(Input, NULL, Output, OutLength, State, UserId);
    }

    Input[i] = 0;
    i++;

    // Skip all spaces
    while ((Input[i] == ' ') && (i < InLength)) {i++;};

    // Check if we are at the end of the received buffer
    if (i == InLength)
    {
        // Only spaces, no parameter
        return InterpretCommand(Input, "", Output, OutLength, State, UserId);
    }

    paramIndex = i;
    Input[InLength] = 0;

    //printf("[%s] [%s] %d\n", Input, &Input[paramIndex], paramIndex);

    return InterpretCommand(Input, &Input[paramIndex], Output, OutLength, State, UserId);
}


int main(int argc, char* argv[])
{
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo *result = NULL;
    struct addrinfo hints;

    int iSendResult;

    int sendSize = 0;
    int recvbuflen = DEFAULT_BUFLEN;
    
    struct sockaddr_in clientInfo;
    int size = sizeof(clientInfo);

    CONNECTION_STATE connState = CONN_INVALID;
    int userId = -1;

	UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind( ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    printf("Listening on port %s...\n\n", DEFAULT_PORT);
    Log("Server started and listening on port %s\n", DEFAULT_PORT);

    // Accept a client socket
    ClientSocket = accept(ListenSocket, (struct sockaddr *)&clientInfo, &size);
    if (ClientSocket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // No longer need server socket
    closesocket(ListenSocket);

    {
        char *connected_ip= inet_ntoa(clientInfo.sin_addr); 
        int port = ntohs(clientInfo.sin_port);
        printf("Connected client: %s:%d\n", connected_ip, port);
    }

    connState = CONN_UNAUTHENTICATED;

    // Receive until the peer shuts down the connection
    do
    {
		//////////////
		clock_t start_time = clock();

        iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);

		clock_t end_time = clock() - start_time;
		double secs = end_time / 1000.0;
		printf("\nSECONDS: %f\n", secs);
		//////////////
		if (iResult > 0 && (secs > 0.1))
		{
			printf(">>>\n");
			printf("Bytes received: %d\n", iResult);

	

			
				{
					if (!ProcessCommand(recvbuf, iResult, sendbuf, &sendSize, &connState, &userId))
					{
						iResult = 0;
					}




				// Echo the buffer back to the sender
				iSendResult = send(ClientSocket, sendbuf, sendSize > DEFAULT_BUFLEN ? DEFAULT_BUFLEN : sendSize, 0);
				if (iSendResult == SOCKET_ERROR) {
					printf("send failed with error: %d\n", WSAGetLastError());
					closesocket(ClientSocket);
					WSACleanup();
					return 1;
				}
				printf("Bytes sent: %d\n", iSendResult);
				printf("<<<\n\n");
			  }
        }
        else if (iResult == 0)
        {
            printf("Connection closing...\n");
        }
        else
        {
            printf("recv failed with error: %d\n", WSAGetLastError());
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }
    } while (iResult > 0);

    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR)
    {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();

	// delete allocated PTRs
	free(last_created_file_name);

    return 0;
}

