package cmd

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lucaspiller/watchsumo-checker/checker"
	"github.com/lucaspiller/watchsumo-checker/metrics"
	pb "github.com/lucaspiller/watchsumo-checker/proto"
	"github.com/lucaspiller/watchsumo-checker/types"
	log "github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
	"google.golang.org/grpc"

	builtinLog "log"
)

const (
	// MaxHeaderKeyLength truncate header keys to this size
	MaxHeaderKeyLength = 50

	// MaxHeaderValueLength truncate header values to this size
	MaxHeaderValueLength = 250

	// MaxBodyLength truncate body to this size
	MaxBodyLength = 250
)

var (
	serverAddr string
	clientID   string
	location   string
	country    string
	env        string

	// Start command
	Start = &cli.Command{
		Name:   "start",
		Action: runStart,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "server",
				Usage:       "grpc server to connect to",
				EnvVars:     []string{"GRPC_SERVER"},
				Destination: &serverAddr,
			},
			&cli.StringFlag{
				Name:        "client_id",
				Usage:       "client id",
				EnvVars:     []string{"GRPC_CLIENT_ID"},
				Destination: &clientID,
			},
			&cli.StringFlag{
				Name:        "location",
				Usage:       "location name",
				EnvVars:     []string{"GRPC_LOCATION"},
				Destination: &location,
			},
			&cli.StringFlag{
				Name:        "country",
				Usage:       "country code",
				EnvVars:     []string{"GRPC_COUNTRY"},
				Destination: &country,
			},
			&cli.StringFlag{
				Name:        "env",
				Usage:       "environment",
				EnvVars:     []string{"APP_ENV"},
				Destination: &env,
			},
		},
	}
)

func truncate(s string, length int) string {
	if len(s) < length {
		return s
	}

	return strings.ToValidUTF8(s[:length], "")
}

func durationToMs(d *time.Duration) int32 {
	return int32(d.Milliseconds())
}

func encodeHeaders(headers http.Header) []*pb.Header {
	var res = []*pb.Header{}

	for k, vs := range headers {
		res = append(res, &pb.Header{
			Key:   truncate(k, MaxHeaderKeyLength),
			Value: truncate(strings.Join(vs, "; "), MaxHeaderValueLength),
		})
	}

	return res
}

func encodeTimestamp(timestamp *time.Time) string {
	return timestamp.Format(time.RFC3339)
}

func startClient(client pb.CheckerServiceClient) {
	ctx := context.Background()
	stream, err := client.Listen(ctx, &pb.CheckerHello{
		Id:       clientID,
		Location: location,
		Country:  country,
	})
	if err != nil {
		log.Fatalf("%v = _, %v", client, err)
	}

	for {
		request, err := stream.Recv()
		if err == io.EOF {
			log.Warn("EOF")
			break
		}
		if err != nil {
			log.Error("Error receiving ", err)
			break
		}

		log.Debug(fmt.Sprintf("< %+v", request))

		go func() {
			var ref string
			if request.MonitoringId != "" {
				ref = request.MonitoringId
			} else {
				ref = request.Caller
			}

			url, err := url.Parse(request.Url)
			if err != nil || url.Host == "" {
				log.WithFields(log.Fields{
					"Ref": ref,
					"Url": request.Url,
					"Err": err,
				}).Error("Invalid URL")
				return
			}

			checkRequest := &types.CheckRequest{
				Ref:     ref,
				Method:  request.Method,
				URL:     url,
				Timeout: time.Duration(request.Timeout) * time.Millisecond,
				Options: types.CheckOptions{
					GetFallback:     request.Options.GetFallback,
					IgnoreTLSErrors: request.Options.IgnoreTlsErrors,
					FollowRedirects: request.Options.FollowRedirects,
				},
			}

			checker := checker.Init(checkRequest)
			checker.Perform()

			var responseStatus pb.Status
			switch checker.Res.Status {
			case types.StatusUp:
				responseStatus = pb.Status_UP
			case types.StatusDown:
				responseStatus = pb.Status_DOWN
			default:
				responseStatus = pb.Status_UNKNOWN
			}

			response := &pb.CheckResponse{
				MonitoringId: request.MonitoringId,
				Caller:       request.Caller,
				Status:       responseStatus,
				Method:       checker.Res.Method,
				Url:          checker.Res.URL.String(),
				StatusCode:   int32(checker.Res.StatusCode),
				Headers:      encodeHeaders(checker.Res.Headers),
				Body:         truncate(checker.Res.Body, MaxBodyLength),
				Time:         durationToMs(checker.Res.Time),
				Error:        checker.Res.Error,
				Timestamp:    encodeTimestamp(checker.Res.Timestamp),
				Proto:        checker.Res.Proto,
				StatusText:   checker.Res.StatusText,
			}

			if checker.Res.Certificate != nil {
				response.Certificate = &pb.CheckResponse_Certificate{
					SerialString:      checker.Res.Certificate.SerialString,
					Algorithm:         int32(checker.Res.Certificate.Algorithm),
					ValidFrom:         encodeTimestamp(&checker.Res.Certificate.ValidFrom),
					ValidTo:           encodeTimestamp(&checker.Res.Certificate.ValidTo),
					Subject:           checker.Res.Certificate.Subject,
					Issuer:            checker.Res.Certificate.Issuer,
					FingerprintSHA256: checker.Res.Certificate.FingerprintSHA256,
					Serial:            checker.Res.Certificate.Serial,
				}
			}

			if checker.Res.Timing != nil {
				response.Timing = &pb.CheckResponse_Timing{
					Dns:        durationToMs(checker.Res.Timing.DNS),
					Connecting: durationToMs(checker.Res.Timing.Connecting),
					Tls:        durationToMs(checker.Res.Timing.TLS),
					Sending:    durationToMs(checker.Res.Timing.Sending),
					Waiting:    durationToMs(checker.Res.Timing.Waiting),
					Receiving:  durationToMs(checker.Res.Timing.Receiving),
				}
			}

			log.WithFields(log.Fields{
				"Ref":    ref,
				"Status": response.Status,
				"Time":   response.Time,
			}).Debug("Check")

			if _, err := client.Result(ctx, response); err != nil {
				log.WithFields(log.Fields{
					"Ref": ref,
					"Err": err,
				}).Error("Error sending gRPC response")
			}
		}()
	}

	stream.CloseSend()
}

func runStart(c *cli.Context) error {
	if env == "development" {
		log.SetLevel(log.DebugLevel)

		metrics.Start(15 * time.Second)
	} else {
		// Disable builtin logger
		builtinLog.SetOutput(ioutil.Discard)

		log.SetLevel(log.InfoLevel)

		metrics.Start(1 * time.Minute)
	}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithBlock())
	opts = append(opts, grpc.WithTimeout(time.Minute))

	log.Info(fmt.Sprintf("Connecting to server %s", serverAddr))
	conn, err := grpc.Dial(serverAddr, opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
		return err
	}
	defer conn.Close()

	log.Info("Connected")

	client := pb.NewCheckerServiceClient(conn)
	startClient(client)

	return nil
}
