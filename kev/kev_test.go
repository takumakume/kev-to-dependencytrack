package kev

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
)

func TestKEV_Init(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := NewMockdbFetcher(ctrl)

	type fields struct {
		db      dbFetcher
		catalog *Catalog
	}
	tests := []struct {
		name       string
		fields     fields
		mockExpect func()
		wantErr    bool
	}{
		{
			name: "needs update",
			fields: fields{
				db:      mockDB,
				catalog: nil,
			},
			mockExpect: func() {
				mockDB.EXPECT().needsUpdate().Return(true, nil)
				mockDB.EXPECT().download().Return(nil)
				mockDB.EXPECT().read().Return([]byte(`{"packages": []}`), nil)
			},
			wantErr: false,
		},
		{
			name: "no update needed",
			fields: fields{
				db:      mockDB,
				catalog: nil,
			},
			mockExpect: func() {
				mockDB.EXPECT().needsUpdate().Return(false, nil)
				mockDB.EXPECT().read().Return([]byte(`{"packages": []}`), nil)
			},
			wantErr: false,
		},
		{
			name: "needs update error",
			fields: fields{
				db:      mockDB,
				catalog: nil,
			},
			mockExpect: func() {
				mockDB.EXPECT().needsUpdate().Return(false, errors.New("error"))
			},
			wantErr: true,
		},
		{
			name: "download error",
			fields: fields{
				db:      mockDB,
				catalog: nil,
			},
			mockExpect: func() {
				mockDB.EXPECT().needsUpdate().Return(true, nil)
				mockDB.EXPECT().download().Return(errors.New("error"))
			},
			wantErr: true,
		},
		{
			name: "read error",
			fields: fields{
				db:      mockDB,
				catalog: nil,
			},
			mockExpect: func() {
				mockDB.EXPECT().needsUpdate().Return(false, nil)
				mockDB.EXPECT().read().Return(nil, errors.New("error"))
			},
			wantErr: true,
		},
		{
			name: "unmarshal error",
			fields: fields{
				db:      mockDB,
				catalog: nil,
			},
			mockExpect: func() {
				mockDB.EXPECT().needsUpdate().Return(false, nil)
				mockDB.EXPECT().read().Return([]byte(`invalid json`), nil)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KEV{
				db:      tt.fields.db,
				catalog: tt.fields.catalog,
			}

			tt.mockExpect()

			err := k.Init()
			if (err != nil) != tt.wantErr {
				t.Errorf("KEV.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
