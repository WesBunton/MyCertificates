package com.wesbunton.projects.mycertificates;

import android.support.v7.widget.RecyclerView;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import java.util.List;

public class TipDataAdapter extends RecyclerView.Adapter {

    private String[] tipData;

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public ViewHolder(View itemView) {
            super(itemView);
        }
    }

    public TipDataAdapter(String[] tipData) {
        this.tipData = tipData;
    }

    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
//        View view = LayoutInflater.from(parent.getContext()).inflate(R.id.txtTip, parent, false);
//        ViewHolder viewHolder = new ViewHolder(view);
        return null;
    }

    @Override
    public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {

    }

    @Override
    public int getItemCount() {
        return tipData.length;
    }
}
