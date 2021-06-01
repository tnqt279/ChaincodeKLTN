package chaincode

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	uuid "github.com/satori/go.uuid"
)

//----STRUCT LIST----
// SmartContract provides functions for managing an Asset
type SmartContract struct {
	contractapi.Contract
}

// Asset describes basic details of what makes up a simple asset
type Asset struct {
	ID             string `json:"ID"`
	Color          string `json:"color"`
	Size           int    `json:"size"`
	Owner          string `json:"owner"`
	AppraisedValue int    `json:"appraisedValue"`
}

type Controller struct {
	ID   string `json:"controllerId"`
	Name string `json:"name"`
}

type Token struct {
	ID string `json:"tokenId"`
}

type Application struct {
	ID   string `json:"applicationId"`
	Name string `json:"applicationName"`
	//Permision string "controller.post"
	Permission []string `json:"permission"`
}

type Log struct {
	LogId        string    `json:"LogId"`
	CreationTime time.Time `json:"creationTime"`
	Application  string    `json:"application"`
	Controller   string    `json:"controller"`
	Status       string    `json:"status"`
	Action       string    `json:"action"`
}

type ClaimsStruct struct {
	App        string    `json:"app"`
	Controller string    `json:"controller"`
	ExpireTime time.Time `json:"expireTime"`
	Permission []string  `json:"permission"`
	jwt.StandardClaims
}

type ProtoController struct {
	ID              string   `json:"controllerId"`
	Name            string   `json:"controllerName"`
	Host_IP         string   `json:"host_ip"`
	Host_Port       string   `json:"host_port"`
	Datapath_id_set []string `json:"datapath_id_set"` //Datapath
	Role            string   `json:"role"`
	Generation_id   string   `json:"generation_id"`
}
type SDNSwitch struct { //datapath
	Datapath_id  string   `json:"datapath_id"`
	Manufacturer string   `json:"manufacturer"`
	Hardware     []string `json:"hardware"`
	Software     []string `json:"sofware"`
	Serial_num   string   `json:"serial_num"`
}
type SDNFlow struct {
	Datapath_id  string   `json:"datapath_id"`
	Length       string   `json:"length"`
	Cookie       string   `json:"cookie"`
	Cookie_mask  string   `json:"cookie_mask"`
	Table_ID     string   `json:"table_id"`
	Priority     string   `json:"priority"`
	Duration_sec string   `json:"duration_sec"` //time live
	Idle_Timeout string   `json:"idle_timeout"`
	Hard_Timeout string   `json:"hard_timeout"`
	Flags        []string `json:"flags"`
	Importance   string   `json:"importance"`
	Packet_count string   `json:"packet_count"`
	Byte_count   string   `json:"byte_count"`
}
type SDNTable struct {
	Datapath_id    string `json:"datapath_id"`
	Table_id       string `json:"table_id"`
	Table_name     string `json:"table_name"`
	Metadata_match string `json:"metadata_match"`
	Metadata_write string `json:"metadata_write"`
	Max_entries    string `json:"max_entries"`
	Active_count   string `json:"active_count"`
	Lookup_count   string `json:"lookup_count"`
	Matched_count  string `json:"matched_count"`
}
type SDNPort struct {
	Datapath_id  string `json:"datapath_id"`
	Port_no      string `json:"port_no"`
	Rx_packets   string `json:"rx_packets"`
	Tx_packets   string `json:"tx_packets"`
	Rx_bytes     string `json:"rx_bytes"`
	Tx_bytes     string `json:"tx_bytes"`
	Rx_dropped   string `json:"rx_dropped"`
	Tx_dropped   string `json:"tx_dropped"`
	Rx_errors    string `json:"rx_errors"`
	Tx_errors    string `json:"tx_errors"`
	Duration_sec string `json:"duration_sec"`
	Properties   string `json:"properties"`
}
type SDNQueue struct {
	Datapath_id  string `json:"datapath_id"`
	Port_no      string `json:"port_no"`
	Queue_id     string `json:"queue_id"`
	Length       string `json:"length"`
	Tx_bytes     string `json:"tx_bytes"`
	Tx_packets   string `json:"tx_packets"`
	Tx_errors    string `json:"tx_errors"`
	Duration_sec string `json:"duration_sec"`
}
type SDNGroups struct {
}
type SDNMeter struct {
}

//----END OF STUCT LIST----

// InitLedger adds a base set of assets to the ledger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	assets := []Asset{
		{ID: "asset1", Color: "blue", Size: 5, Owner: "Tomoko", AppraisedValue: 300},
		{ID: "asset2", Color: "red", Size: 5, Owner: "Brad", AppraisedValue: 400},
		{ID: "asset3", Color: "green", Size: 10, Owner: "Jin Soo", AppraisedValue: 500},
		{ID: "asset4", Color: "yellow", Size: 10, Owner: "Max", AppraisedValue: 600},
		{ID: "asset5", Color: "black", Size: 15, Owner: "Adriana", AppraisedValue: 700},
		{ID: "asset6", Color: "white", Size: 15, Owner: "Michel", AppraisedValue: 800},
	}

	for _, asset := range assets {
		assetJSON, err := json.Marshal(asset)
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState(asset.ID, assetJSON)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
	}

	return nil
}

// CreateAsset issues a new asset to the world state with given details.
func (s *SmartContract) CreateAsset(ctx contractapi.TransactionContextInterface, id string, color string, size int, owner string, appraisedValue int) error {
	exists, err := s.AssetExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the asset %s already exists", id)
	}

	asset := Asset{
		ID:             id,
		Color:          color,
		Size:           size,
		Owner:          owner,
		AppraisedValue: appraisedValue,
	}
	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, assetJSON)
}

func (s *SmartContract) CreateController(ctx contractapi.TransactionContextInterface, id string, name string) error {
	exists, err := s.AssetExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the asset %s already exists", id)
	}

	asset := Controller{
		ID:   id,
		Name: name,
	}
	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, assetJSON)
}

func (s *SmartContract) CreateApplication(ctx contractapi.TransactionContextInterface, id string, name string, permission []string) error {
	exists, err := s.AssetExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the asset %s already exists", id)
	}
	//permissions := json.Unmarshal(permission, &permissions)
	asset := Application{
		ID:         id,
		Name:       name,
		Permission: permission,
	}
	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, assetJSON)
}

// ReadAsset returns the asset stored in the world state with given id.
func (s *SmartContract) ReadAsset(ctx contractapi.TransactionContextInterface, id string) (*Asset, error) {
	assetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if assetJSON == nil {
		return nil, fmt.Errorf("the asset %s does not exist", id)
	}

	var asset Asset
	err = json.Unmarshal(assetJSON, &asset)
	if err != nil {
		return nil, err
	}

	return &asset, nil
}

// UpdateAsset updates an existing asset in the world state with provided parameters.
func (s *SmartContract) UpdateAsset(ctx contractapi.TransactionContextInterface, id string, color string, size int, owner string, appraisedValue int) error {
	exists, err := s.AssetExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the asset %s does not exist", id)
	}

	// overwriting original asset with new asset
	asset := Asset{
		ID:             id,
		Color:          color,
		Size:           size,
		Owner:          owner,
		AppraisedValue: appraisedValue,
	}
	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, assetJSON)
}

// DeleteAsset deletes an given asset from the world state.
func (s *SmartContract) DeleteAsset(ctx contractapi.TransactionContextInterface, id string) error {
	exists, err := s.AssetExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the asset %s does not exist", id)
	}

	return ctx.GetStub().DelState(id)
}

// AssetExists returns true when asset with given ID exists in world state
func (s *SmartContract) AssetExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return assetJSON != nil, nil
}

// TransferAsset updates the owner field of asset with given id in world state.
func (s *SmartContract) TransferAsset(ctx contractapi.TransactionContextInterface, id string, newOwner string) error {
	asset, err := s.ReadAsset(ctx, id)
	if err != nil {
		return err
	}

	asset.Owner = newOwner
	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, assetJSON)
}

// GetAllAssets returns all assets found in world state
func (s *SmartContract) GetAllAssets(ctx contractapi.TransactionContextInterface) ([]*Asset, error) {
	// range query with empty string for startKey and endKey does an
	// open-ended query of all assets in the chaincode namespace.
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var assets []*Asset
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var asset Asset
		err = json.Unmarshal(queryResponse.Value, &asset)
		if err != nil {
			return nil, err
		}
		assets = append(assets, &asset)
	}

	var tempasset = Asset{
		ID:             "tempID",
		Color:          "tempcolor",
		Size:           6969,
		Owner:          "tempowner",
		AppraisedValue: 6969,
	}
	assets = append(assets, &tempasset)

	return assets, nil
}

//func for authentication
func GenerateJwt(controller string, time time.Time, permission []string, application string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"controller":  controller,
		"expireTime":  time,
		"application": application,
		"permission":  permission,
	})
	return token.SignedString([]byte("17521195"))
}

//Check Controller Permission
func CheckPermision(a []string, x string) bool {
	for _, n := range a {
		// n : "controller.action"
		check := strings.Split(n, ".")[0]
		if x == check {
			return true
		}
	}
	return false
}

func CheckActionController(a []string, controller string, action string) bool {
	for _, n := range a {
		// n : "controller.action"
		check := strings.Split(n, ".")
		if controller == check[0] && action == check[1] {
			return true
		}
	}
	return false
}

func ParseJwt(token string) (*ClaimsStruct, error) {

	res, err := jwt.ParseWithClaims(token, &ClaimsStruct{}, func(tokenJwt *jwt.Token) (interface{}, error) {
		return []byte("17521195"), nil
	})

	claims := res.Claims.(*ClaimsStruct)
	return claims, err
}

func (s *SmartContract) Authentication(ctx contractapi.TransactionContextInterface, applicationId string, controllerId string) (string, error) {
	applicationJSON, err := ctx.GetStub().GetState(applicationId)
	if err != nil {
		return "failed to read from world state: %v", err
	}
	if applicationJSON == nil {
		return "the asset %s does not exist", err //
	}

	controllerJSON, err1 := ctx.GetStub().GetState(controllerId)
	if err1 != nil {
		return "failed to read from world state: %v", err
	}
	if controllerJSON == nil {
		return "the asset %s does not exist", err //
	}

	var app Application
	err = json.Unmarshal(applicationJSON, &app)
	if err != nil {
		return "nil", err
	}

	var controller Controller
	err = json.Unmarshal(controllerJSON, &controller)
	if err != nil {
		return "nil", err
	}

	if !CheckPermision(app.Permission, controllerId) {
		return "app does not have permission", err
	}

	currentTime := time.Now()
	token, err := GenerateJwt(controller.ID, currentTime, app.Permission, app.ID)

	exists, err := s.AssetExists(ctx, token)
	if err != nil {
		return "fail to generate token", err
	}
	if exists {
		return "token is already exists", err
	}

	asset := Token{
		ID: token,
	}
	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return "fail to generate token", err
	}

	ctx.GetStub().PutState(token, assetJSON)
	return token, err
}

func (s *SmartContract) Authorization(ctx contractapi.TransactionContextInterface, token string, controllerId string, action string, application string) string {
	tokenJson, errToken := ParseJwt(token)
	tokenParse, errTokenParse := s.AssetExists(ctx, token)
	now := time.Now()
	//tam tho sua the cho k co loi
	//guid, errGuid := uuid.NewV4()
	guid := uuid.NewV4()
	//if errGuid != nil {
	//	return "fail to generate log"
	//}
	guidString := guid.String()
	// Token not exist
	if errToken != nil || errTokenParse != nil || !tokenParse {
		asset := Log{
			LogId:        guidString,
			CreationTime: now,
			Application:  application,
			Controller:   controllerId,
			Status:       "Fail",
			Action:       action,
		}
		assetJSON, err := json.Marshal(asset)
		if err != nil {
			return "Unable to marshal asset to json"
		}

		ctx.GetStub().PutState(guidString, assetJSON)
		return "Token invalid"
	}

	//Token expire
	if now.After(tokenJson.ExpireTime) {
		asset := Log{
			LogId:        guidString,
			CreationTime: now,
			Application:  application,
			Controller:   controllerId,
			Status:       "Fail",
			Action:       action,
		}
		assetJSON, err := json.Marshal(asset)
		if err != nil {
			return "fail to generate log"
		}

		ctx.GetStub().PutState(guidString, assetJSON)
		return "Token expire"
	}

	//invalid permission
	if !CheckActionController(tokenJson.Permission, controllerId, action) {
		asset := Log{
			LogId:        guidString,
			CreationTime: now,
			Application:  application,
			Controller:   controllerId,
			Status:       "Fail",
			Action:       action,
		}
		assetJSON, err := json.Marshal(asset)
		if err != nil {
			return "fail to generate log"
		}

		ctx.GetStub().PutState(guidString, assetJSON)
		return "Token invalid"
	}

	//invalid owner token
	if application != tokenJson.App {
		asset := Log{
			LogId:        guidString,
			CreationTime: now,
			Application:  application,
			Controller:   controllerId,
			Status:       "Fail",
			Action:       action,
		}
		assetJSON, err := json.Marshal(asset)
		if err != nil {
			return "fail to generate log"
		}

		ctx.GetStub().PutState(guidString, assetJSON)
		return "Token invalid"
	}

	asset := Log{
		LogId:        guidString,
		CreationTime: now,
		Application:  application,
		Controller:   controllerId,
		Status:       "Success",
		Action:       action,
	}
	assetJSON, errAsset := json.Marshal(asset)
	if errAsset != nil {
		return "fail to generate log"
	}

	ctx.GetStub().PutState(guidString, assetJSON)
	return "valid token"
}
