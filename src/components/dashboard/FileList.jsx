import React from 'react';
import FileItem from './FileItem';
import FolderItem from './FolderItem';
// import '../../styles/DashboardPage.css';

const FileList = ({ items, onFolderClick, onFileClick }) => {
  if (!items || items.length === 0) {
    return <div className="file-list"><p>这个文件夹是空的。</p></div>;
  }

  const folders = items.filter(item => item.isDirectory);
  const files = items.filter(item => item.isFile);

  return (
    <div className="file-list">
      {folders.map(item => (
        <FolderItem key={item.name} item={item} onClick={() => onFolderClick(item)} />
      ))}
      {files.map(item => (
        <FileItem key={item.name} item={item} onClick={() => onFileClick(item)} />
      ))}
    </div>
  );
};

export default FileList;
